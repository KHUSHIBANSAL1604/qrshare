"""Expiration: boundaries, enforcement on every path, and the expired page."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from conftest import share_row

from app.extensions import db

JSON = {"Accept": "application/json"}


def set_expiry(app, token, **delta):
    with app.app_context():
        share = share_row(token)
        share.expires_at = datetime.now(timezone.utc) + timedelta(**delta)
        db.session.commit()


def test_active_share_is_downloadable(fresh_client, make_share, app):
    body = make_share()
    set_expiry(app, body["token"], minutes=5)
    assert fresh_client.get(f"/api/share/{body['token']}/download").status_code == 200


def test_expired_share_is_refused_with_410(fresh_client, make_share, app):
    body = make_share()
    set_expiry(app, body["token"], seconds=-1)
    response = fresh_client.get(f"/api/share/{body['token']}/download", headers=JSON)
    assert response.status_code == 410
    assert response.get_json()["code"] == "expired"


def test_expiry_boundary_one_second_before_and_after(fresh_client, make_share, app):
    """Just inside the window works; just outside does not."""
    body = make_share()

    set_expiry(app, body["token"], seconds=2)
    assert fresh_client.get(f"/api/share/{body['token']}/download").status_code == 200

    set_expiry(app, body["token"], seconds=-1)
    assert fresh_client.get(f"/api/share/{body['token']}/download", headers=JSON).status_code == 410


def test_expiry_is_inclusive_at_the_exact_deadline(app, make_share):
    """At exactly expires_at the share is already expired (>= comparison)."""
    body = make_share()
    with app.app_context():
        share = share_row(body["token"])
        share.expires_at = datetime.now(timezone.utc)
        db.session.commit()
        assert share_row(body["token"]).is_expired is True


def test_expired_receiver_page_explains_itself(fresh_client, make_share, app):
    body = make_share()
    set_expiry(app, body["token"], seconds=-1)
    page = fresh_client.get(f"/s/{body['token']}").get_data(as_text=True)
    assert "Share expired" in page
    assert "no longer available" in page
    assert "Download file" not in page
    assert "Return home" in page


def test_expired_page_does_not_leak_internals(fresh_client, make_share, app, storage_dir):
    body = make_share()
    set_expiry(app, body["token"], seconds=-1)
    page = fresh_client.get(f"/s/{body['token']}").get_data(as_text=True)
    assert str(storage_dir) not in page
    assert "Traceback" not in page
    assert ".enc" not in page
    with app.app_context():
        assert share_row(body["token"]).file.stored_filename not in page


def test_expired_share_refuses_password_verification(fresh_client, make_share, app):
    body = make_share(password_protect="true", password="abcdef1", password_confirm="abcdef1")
    set_expiry(app, body["token"], seconds=-1)
    response = fresh_client.post(
        f"/api/share/{body['token']}/verify-password", json={"password": "abcdef1"}
    )
    assert response.status_code == 410


def test_a_valid_ticket_does_not_survive_expiry(fresh_client, make_share, app):
    """State is checked before the ticket, so an unlocked share still dies."""
    body = make_share(password_protect="true", password="abcdef1", password_confirm="abcdef1")
    ticket = fresh_client.post(
        f"/api/share/{body['token']}/verify-password", json={"password": "abcdef1"}
    ).get_json()["ticket"]

    set_expiry(app, body["token"], seconds=-1)
    response = fresh_client.get(
        f"/api/share/{body['token']}/download?ticket={ticket}", headers=JSON
    )
    assert response.status_code == 410


def test_status_endpoint_reports_expired(fresh_client, make_share, app):
    body = make_share()
    set_expiry(app, body["token"], seconds=-1)
    data = fresh_client.get(f"/api/share/{body['token']}/status").get_json()
    assert data["status"] == "expired"
    assert data["seconds_remaining"] == 0


def test_seconds_remaining_counts_down(app, make_share):
    body = make_share()
    set_expiry(app, body["token"], minutes=10)
    with app.app_context():
        remaining = share_row(body["token"]).seconds_remaining
    assert 590 <= remaining <= 600


def test_expiry_survives_a_database_round_trip(app, make_share):
    """SQLite drops tzinfo; the model must re-attach UTC rather than compare
    an aware value against a naive one."""
    body = make_share(expiry_minutes="10")
    with app.app_context():
        db.session.expire_all()
        share = share_row(body["token"])
        assert share.expires_at_utc.tzinfo is not None
        assert share.is_expired is False


# -- timezone handling across a fresh session -------------------------------
def test_all_datetime_columns_come_back_timezone_aware(app, make_share, fresh_client):
    """Regression: SQLite discards tzinfo, and within one session the identity
    map hides it. Only after expunging does a naive value surface -- which is
    how a bug here reaches a cron job while passing the test suite."""
    from datetime import timezone as tz

    from app.models import AuditLog

    body = make_share(one_time="true")
    fresh_client.get(f"/api/share/{body['token']}/download")

    with app.app_context():
        db.session.expunge_all()  # force a genuine reload from the database
        share = share_row(body["token"])
        for field in ("created_at", "expires_at", "last_accessed_at"):
            value = getattr(share, field)
            assert value is not None, field
            assert value.tzinfo is not None, f"{field} came back naive"
            assert value.utcoffset() == tz.utc.utcoffset(None), field

        assert share.file.uploaded_at.tzinfo is not None
        entry = db.session.query(AuditLog).first()
        assert entry.timestamp.tzinfo is not None


def test_cleanup_runs_against_a_reloaded_session(app, make_share, services, fresh_client):
    """The exact shape of the `manage.py cleanup` failure: a consumed share
    reloaded in a fresh session must not blow up on datetime comparison."""
    body = make_share(one_time="true")
    fresh_client.get(f"/api/share/{body['token']}/download")
    with app.app_context():
        share = share_row(body["token"])
        share.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        share.last_accessed_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db.session.commit()
        db.session.expunge_all()

        report = services.cleanup.run()
        assert report.errors == []
        assert report.blobs_deleted == 1
