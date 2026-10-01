"""Share lifecycle: creation, authorisation, atomic consumption, cancellation."""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import update

from app.extensions import db
from app.models import AuditEvent, Share, ShareStatus, StoredFile
from app.services.audit_service import AuditService
from app.utils.formatting import iso
from app.utils.passwords import hash_password, verify_password

logger = logging.getLogger(__name__)

#: bytes of entropy in a public share token (~256 bits before encoding)
TOKEN_BYTES = 32
TICKET_SALT = "qrshare.download.ticket"


class ShareError(Exception):
    """A share operation the caller may not perform.

    ``status`` is the HTTP status to return and ``code`` a stable machine
    string for the frontend. The message is safe to display.
    """

    def __init__(self, message: str, *, status: int = 400, code: str = "error") -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


class ShareService:
    """All share business rules live here, not in route handlers."""

    def __init__(self, secret_key: str, ticket_ttl: int = 300) -> None:
        self._serializer = URLSafeTimedSerializer(secret_key, salt=TICKET_SALT)
        self.ticket_ttl = ticket_ttl

    # -- creation ----------------------------------------------------------
    @staticmethod
    def generate_token() -> str:
        """Unpredictable, URL-safe bearer token.

        ``secrets`` draws from the OS CSPRNG. Nothing about the file, the
        database id or the clock feeds into it, so tokens leak no information
        and cannot be enumerated.
        """
        return secrets.token_urlsafe(TOKEN_BYTES)

    def create_share(
        self,
        stored_file: StoredFile,
        *,
        expiry_minutes: int,
        password: str | None = None,
        one_time: bool = False,
    ) -> Share:
        """Build a share row (not committed -- the caller commits)."""
        now = datetime.now(timezone.utc)
        share = Share(
            file=stored_file,
            token=self.generate_token(),
            owner_token=self.generate_token(),
            created_at=now,
            expires_at=now + timedelta(minutes=expiry_minutes),
            password_hash=hash_password(password) if password else None,
            one_time=bool(one_time),
            used=False,
            downloads=0,
        )
        db.session.add(share)
        return share

    # -- lookup ------------------------------------------------------------
    @staticmethod
    def get_by_token(token: str | None) -> Share | None:
        """Look up a share by its public token.

        Returns ``None`` for anything that is not a plausible token so a
        malformed value never reaches the database as a wildcard.
        """
        if not token or not (16 <= len(token) <= 64) or not _is_urlsafe(token):
            return None
        return db.session.query(Share).filter(Share.token == token).one_or_none()

    @staticmethod
    def owns(share: Share, owner_token: str | None) -> bool:
        """Constant-time check that the caller created this share."""
        if not owner_token:
            return False
        return secrets.compare_digest(share.owner_token, owner_token)

    # -- authorisation -----------------------------------------------------
    @staticmethod
    def assert_downloadable(share: Share) -> None:
        """Raise the right error for a share that cannot be downloaded."""
        status = share.status
        if status is ShareStatus.ACTIVE:
            return
        if status is ShareStatus.USED:
            raise ShareError(
                "This link was a one-time download and has already been used.",
                status=410,
                code="used",
            )
        if status is ShareStatus.EXPIRED:
            raise ShareError(
                "This sharing link has expired.", status=410, code="expired"
            )
        raise ShareError("This sharing link is no longer available.", status=410, code="deleted")

    def check_password(self, share: Share, password: str | None) -> bool:
        """Verify a share password and audit the outcome.

        Runs the hash comparison even when the share has no password, so the
        response timing does not reveal whether protection is enabled.
        """
        ok = verify_password(share.password_hash, password)
        if not share.is_password_protected:
            return False
        AuditService.record(
            AuditEvent.PASSWORD_OK if ok else AuditEvent.PASSWORD_FAILED,
            share_id=share.id,
            success=ok,
            reason=None if ok else "bad_password",
            commit=True,
        )
        return ok

    # -- download tickets --------------------------------------------------
    def issue_ticket(self, share: Share) -> str:
        """Short-lived proof that this browser already entered the password.

        Lets the actual download be a plain ``GET`` (so the browser downloads
        natively) without ever putting the password in a URL. The ticket is
        bound to the share's token *and* to a fingerprint of its password
        hash, so rotating the password invalidates outstanding tickets.
        """
        return self._serializer.dumps({"t": share.token, "f": _hash_fingerprint(share)})

    def verify_ticket(self, share: Share, ticket: str | None) -> bool:
        if not ticket:
            return False
        try:
            payload: Any = self._serializer.loads(ticket, max_age=self.ticket_ttl)
        except SignatureExpired:
            return False
        except BadSignature:
            logger.warning("rejected a download ticket with a bad signature")
            return False
        if not isinstance(payload, dict):
            return False
        return bool(
            secrets.compare_digest(str(payload.get("t", "")), share.token)
            and secrets.compare_digest(str(payload.get("f", "")), _hash_fingerprint(share))
        )

    def authorize_download(self, share: Share, ticket: str | None) -> None:
        """Full gate in front of the bytes: state first, then password."""
        self.assert_downloadable(share)
        if share.is_password_protected and not self.verify_ticket(share, ticket):
            raise ShareError(
                "This file is password protected.", status=401, code="password_required"
            )

    # -- consumption -------------------------------------------------------
    @staticmethod
    def claim_download(share: Share) -> bool:
        """Atomically register one successful download.

        For a one-time share this is the moment of consumption. The guard
        ``used = 0`` lives in the ``UPDATE`` statement itself, so if two
        requests race, the database serialises them and exactly one sees
        ``rowcount == 1``; the loser is refused. Nothing is streamed before
        this returns ``True``, so a one-time link can never be served twice.
        """
        now = datetime.now(timezone.utc)
        values: dict[str, Any] = {
            "downloads": Share.downloads + 1,
            "last_accessed_at": now,
        }
        conditions = [Share.id == share.id, Share.deleted_at.is_(None)]
        if share.one_time:
            values["used"] = True
            conditions.append(Share.used.is_(False))

        result = db.session.execute(update(Share).where(*conditions).values(**values))
        if result.rowcount != 1:
            db.session.rollback()
            return False
        AuditService.record(
            AuditEvent.SHARE_CONSUMED if share.one_time else AuditEvent.DOWNLOAD_SUCCESS,
            share_id=share.id,
            success=True,
        )
        db.session.commit()
        db.session.refresh(share)
        return True

    @staticmethod
    def blob_is_unreferenced(share: Share) -> bool:
        """True when no *other* live share still needs this file's bytes.

        Today one upload produces exactly one share, so this is always true --
        but deleting a blob out from under a sibling share would be a silent
        data-loss bug the moment that stops holding.
        """
        from sqlalchemy import func, select

        live = db.session.scalar(
            select(func.count(Share.id)).where(
                Share.file_id == share.file_id,
                Share.id != share.id,
                Share.deleted_at.is_(None),
            )
        )
        return not live

    @staticmethod
    def cancel(share: Share) -> None:
        """Owner-initiated revocation: expire now and mark for cleanup."""
        now = datetime.now(timezone.utc)
        share.expires_at = now
        share.deleted_at = now
        AuditService.record(AuditEvent.SHARE_CANCELLED, share_id=share.id, success=True)
        db.session.commit()

    # -- serialisation -----------------------------------------------------
    @staticmethod
    def public_status(share: Share) -> dict[str, Any]:
        """What a *receiver* is allowed to know.

        Deliberately excludes database ids, storage paths, the owner token and
        the audit trail.
        """
        return {
            "status": share.status.value,
            "filename": share.file.original_filename,
            "size": share.file.size,
            "expires_at": iso(share.expires_at_utc),
            "seconds_remaining": share.seconds_remaining,
            "downloads": share.downloads,
            "one_time": share.one_time,
            "password_protected": share.is_password_protected,
        }

    @classmethod
    def owner_status(cls, share: Share) -> dict[str, Any]:
        """Adds sender-only fields on top of the public view."""
        data = cls.public_status(share)
        data.update(
            {
                "created_at": iso(share.created_at),
                "last_accessed_at": iso(share.last_accessed_at),
                "used": share.used,
            }
        )
        return data


def _hash_fingerprint(share: Share) -> str:
    """Non-reversible marker of the current password hash.

    Only ever used to invalidate tickets; the hash itself never leaves the
    server and the digest is not a credential.
    """
    return hashlib.sha256((share.password_hash or "").encode()).hexdigest()[:16]


def _is_urlsafe(value: str) -> bool:
    return all(ch.isalnum() or ch in "-_" for ch in value)
