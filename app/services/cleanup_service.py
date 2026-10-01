"""Removal of data that has outlived its purpose.

Three jobs, all idempotent so they can run on a timer, from a cron entry, or
by hand without coordination:

* shred the blob behind expired and consumed shares once a grace period has
  passed (the grace window keeps the "expired"/"already used" message
  available to a receiver who scans just too late);
* drop rows for shares whose blob is gone and whose grace window is over;
* delete orphaned blobs that no database row references.

No Redis and no Celery: a daemon thread inside the app process is enough for
the MVP, and the same entry point is exposed as a CLI command for anyone who
prefers cron.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.extensions import db
from app.models import AuditEvent, Share, StoredFile
from app.services.audit_service import AuditService
from app.services.file_service import FileService
from app.services.share_service import ShareService

logger = logging.getLogger(__name__)


@dataclass
class CleanupReport:
    blobs_deleted: int = 0
    shares_purged: int = 0
    files_purged: int = 0
    orphans_deleted: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, int | list[str]]:
        return {
            "blobs_deleted": self.blobs_deleted,
            "shares_purged": self.shares_purged,
            "files_purged": self.files_purged,
            "orphans_deleted": self.orphans_deleted,
            "errors": self.errors,
        }

    @property
    def total(self) -> int:
        return self.blobs_deleted + self.shares_purged + self.orphans_deleted


class CleanupService:
    """Sweeps expired, consumed and orphaned data."""

    def __init__(self, file_service: FileService, grace_minutes: int = 10) -> None:
        self.files = file_service
        self.grace = timedelta(minutes=grace_minutes)

    # -- individual passes -------------------------------------------------
    def shred_dead_shares(self, report: CleanupReport) -> None:
        """Delete the encrypted bytes behind shares nobody may download.

        Runs in small batches and commits per share, so a long sweep never
        holds a write lock over the whole table.
        """
        now = datetime.now(timezone.utc)
        cutoff = now - self.grace
        candidates = db.session.scalars(
            select(Share).where(Share.deleted_at.is_(None)).order_by(Share.id).limit(500)
        ).all()

        for share in candidates:
            consumed = share.one_time and share.used
            expired = share.expires_at_utc <= cutoff
            if not (expired or (consumed and (share.last_accessed_at or now) <= cutoff)):
                continue
            try:
                if ShareService.blob_is_unreferenced(share):
                    if self.files.delete_blob(share.file):
                        report.blobs_deleted += 1
                share.deleted_at = now
                AuditService.record(
                    AuditEvent.FILE_DELETED,
                    share_id=share.id,
                    success=True,
                    reason="expired" if expired else "consumed",
                )
                db.session.commit()
            except Exception as exc:  # noqa: BLE001 - a bad row must not stop the sweep
                db.session.rollback()
                logger.exception("cleanup failed for a share")
                report.errors.append(type(exc).__name__)

    def purge_rows(self, report: CleanupReport) -> None:
        """Drop metadata whose blob is already gone and whose grace has run out.

        Audit rows cascade with the share. That is intentional: keeping an
        indefinite record of every IP that touched a deleted file would be a
        privacy liability, not a security win.
        """
        cutoff = datetime.now(timezone.utc) - self.grace
        stale = db.session.scalars(
            select(Share)
            .where(Share.deleted_at.is_not(None), Share.deleted_at <= cutoff)
            .limit(500)
        ).all()
        for share in stale:
            db.session.delete(share)
            report.shares_purged += 1
        db.session.commit()

        orphan_files = db.session.scalars(
            select(StoredFile).where(~StoredFile.shares.any()).limit(500)
        ).all()
        for record in orphan_files:
            self.files.delete_blob(record)
            db.session.delete(record)
            report.files_purged += 1
        db.session.commit()

    def delete_orphan_blobs(self, report: CleanupReport) -> None:
        """Remove files on disk that no row points at (crash recovery)."""
        known = {
            row[0]
            for row in db.session.execute(select(StoredFile.stored_filename)).all()
        }
        for key in list(self.files.storage.list_keys()):
            if key not in known and self.files.storage.delete(key):
                report.orphans_deleted += 1

    # -- entry point -------------------------------------------------------
    def run(self) -> CleanupReport:
        report = CleanupReport()
        self.shred_dead_shares(report)
        self.purge_rows(report)
        self.delete_orphan_blobs(report)
        if report.total:
            logger.info("cleanup sweep: %s", report.as_dict())
        return report


def start_background_cleanup(app, interval_seconds: int) -> threading.Thread | None:
    """Run :meth:`CleanupService.run` on a timer inside the app process.

    Returns ``None`` when disabled. The thread is a daemon so it never keeps
    the process alive, and every sweep is wrapped so a failure only skips one
    cycle.
    """
    if interval_seconds <= 0:
        return None

    stop = threading.Event()

    def loop() -> None:
        # An initial delay keeps startup snappy and avoids racing the very
        # first request while the schema is still being created.
        while not stop.wait(interval_seconds):
            try:
                with app.app_context():
                    app.extensions["qrshare"].cleanup.run()
            except Exception:  # noqa: BLE001 - never kill the sweeper
                logger.exception("background cleanup sweep failed")

    thread = threading.Thread(target=loop, name="qrshare-cleanup", daemon=True)
    thread.start()
    app.extensions.setdefault("qrshare_cleanup_stop", stop)
    logger.info("background cleanup running every %ss", interval_seconds)
    return thread
