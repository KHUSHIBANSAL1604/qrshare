"""Cleanup sweeps: expired shares, consumed one-time shares, orphaned blobs."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from conftest import share_row

from app.extensions import db
from app.models import AuditLog, Share, StoredFile

JSON = {"Accept": "application/json"}


def age_share(app, token, minutes):
    """Push a share's timestamps into the past so it is past the grace window."""
    with app.app_context():
        share = share_row(token)
        share.expires_at = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        if share.last_accessed_at:
            share.last_accessed_at = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        db.session.commit()


def test_active_shares_are_left_alone(app, make_share, services, storage_dir):
    make_share()
    with app.app_context():
        report = services.cleanup.run()
    assert report.blobs_deleted == 0
    assert len(list(storage_dir.iterdir())) == 1


def test_expired_share_blob_is_shredded(app, make_share, services, storage_dir):
    body = make_share()
    age_share(app, body["token"], minutes=60)

    with app.app_context():
        report = services.cleanup.run()

    assert report.blobs_deleted == 1
    assert not list(storage_dir.iterdir())
    with app.app_context():
        assert share_row(body["token"]).status.value == "deleted"


def test_share_inside_the_grace_window_survives(app, make_share, services, storage_dir):
    """Just-expired shares stay so the receiver still gets a clear message."""
    body = make_share()
    with app.app_context():
        share = share_row(body["token"])
        share.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        db.session.commit()
        services.cleanup.run()
    assert len(list(storage_dir.iterdir())) == 1
    with app.app_context():
        assert share_row(body["token"]).deleted_at is None


def test_consumed_one_time_share_is_cleaned(app, make_share, services, storage_dir, fresh_client):
    body = make_share(one_time="true")
    assert fresh_client.get(f"/api/share/{body['token']}/download").status_code == 200
    age_share(app, body["token"], minutes=60)

    with app.app_context():
        report = services.cleanup.run()

    assert report.blobs_deleted == 1
    assert not list(storage_dir.iterdir())


def test_cleanup_records_a_file_deleted_audit_event(app, make_share, services):
    body = make_share()
    age_share(app, body["token"], minutes=60)
    with app.app_context():
        services.cleanup.run()
        share = share_row(body["token"])
        events = [
            row.event_type
            for row in db.session.query(AuditLog).filter(AuditLog.share_id == share.id)
        ]
        assert "FILE_DELETED" in events


def test_orphan_blobs_are_removed(app, services, storage_dir):
    """A blob left by a crashed upload must not linger forever."""
    orphan = storage_dir / (("a1" * 12) + ".enc")
    orphan.write_bytes(b"QRS1 leftover from a crash")
    assert orphan.exists()

    with app.app_context():
        report = services.cleanup.run()

    assert report.orphans_deleted == 1
    assert not orphan.exists()


def test_cleanup_ignores_unrecognised_files_in_storage(app, services, storage_dir):
    """Only files matching our own key pattern are ever deleted."""
    stray = storage_dir / "README.txt"
    stray.write_text("not ours")
    with app.app_context():
        services.cleanup.run()
    assert stray.exists()


def test_rows_are_purged_after_the_grace_period(app, make_share, services):
    body = make_share()
    age_share(app, body["token"], minutes=60)

    with app.app_context():
        services.cleanup.run()  # marks deleted_at
        share = share_row(body["token"])
        share.deleted_at = datetime.now(timezone.utc) - timedelta(minutes=60)
        db.session.commit()

        report = services.cleanup.run()  # now purges the row
        assert report.shares_purged == 1
        assert db.session.query(Share).count() == 0
        # The file row goes too, since nothing references it any more.
        assert db.session.query(StoredFile).count() == 0


def test_audit_rows_are_removed_with_their_share(app, make_share, services):
    body = make_share()
    age_share(app, body["token"], minutes=60)
    with app.app_context():
        services.cleanup.run()
        share = share_row(body["token"])
        share.deleted_at = datetime.now(timezone.utc) - timedelta(minutes=60)
        db.session.commit()
        services.cleanup.run()
        assert db.session.query(AuditLog).count() == 0


def test_cleanup_is_idempotent(app, make_share, services, storage_dir):
    body = make_share()
    age_share(app, body["token"], minutes=60)
    with app.app_context():
        first = services.cleanup.run()
        second = services.cleanup.run()
    assert first.blobs_deleted == 1
    assert second.blobs_deleted == 0
    assert not second.errors
    assert not list(storage_dir.iterdir())


def test_cleaned_share_is_no_longer_downloadable(app, make_share, services, fresh_client):
    body = make_share()
    age_share(app, body["token"], minutes=60)
    with app.app_context():
        services.cleanup.run()
    response = fresh_client.get(f"/api/share/{body['token']}/download", headers=JSON)
    assert response.status_code == 410


def test_cleanup_reports_no_errors_on_a_healthy_database(app, make_share, services):
    make_share()
    make_share(one_time="true")
    with app.app_context():
        assert services.cleanup.run().errors == []
