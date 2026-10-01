"""Download endpoint: correct bytes, headers, counting, and one-time semantics."""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from conftest import share_row

from app.extensions import db
from app.models import AuditLog

JSON = {"Accept": "application/json"}


def unlock(client, token, password):
    response = client.post(f"/api/share/{token}/verify-password", json={"password": password})
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()["ticket"]


# -- happy path ------------------------------------------------------------
def test_download_returns_the_original_bytes(fresh_client, make_share):
    content = b"\x00\x01binary payload\xff" * 500
    body = make_share(content=content, filename="data.bin")
    response = fresh_client.get(f"/api/share/{body['token']}/download")
    assert response.status_code == 200
    assert response.data == content


def test_download_headers_are_safe(fresh_client, make_share):
    body = make_share(content=b"<html>not html</html>", filename="page.html")
    response = fresh_client.get(f"/api/share/{body['token']}/download")
    disposition = response.headers["Content-Disposition"]
    assert disposition.startswith("attachment")
    assert "page.html" in disposition
    # Never served as a renderable type on our own origin.
    assert response.headers["Content-Type"] == "application/octet-stream"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "no-store" in response.headers["Cache-Control"]


def test_content_length_matches_the_plaintext(fresh_client, make_share):
    content = b"x" * 3333
    body = make_share(content=content)
    response = fresh_client.get(f"/api/share/{body['token']}/download")
    assert response.headers["Content-Length"] == "3333"
    assert len(response.data) == 3333


def test_unicode_filename_survives_the_round_trip(fresh_client, make_share):
    body = make_share(filename="rapport-été-2026.pdf")
    response = fresh_client.get(f"/api/share/{body['token']}/download")
    assert response.status_code == 200
    # RFC 5987 encoding keeps non-ASCII names intact.
    assert "filename*=UTF-8''" in response.headers["Content-Disposition"]


# -- counting --------------------------------------------------------------
def test_download_count_increments_on_success(fresh_client, make_share, app):
    body = make_share()
    for expected in (1, 2, 3):
        assert fresh_client.get(f"/api/share/{body['token']}/download").status_code == 200
        with app.app_context():
            assert share_row(body["token"]).downloads == expected


def test_failed_password_does_not_count_as_a_download(fresh_client, make_share, app):
    body = make_share(password_protect="true", password="correct-horse", password_confirm="correct-horse")
    fresh_client.post(f"/api/share/{body['token']}/verify-password", json={"password": "wrong"})
    assert fresh_client.get(f"/api/share/{body['token']}/download", headers=JSON).status_code == 401
    with app.app_context():
        assert share_row(body["token"]).downloads == 0


def test_expired_request_does_not_count_as_a_download(fresh_client, make_share, app):
    body = make_share()
    with app.app_context():
        share = share_row(body["token"])
        share.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()
    assert fresh_client.get(f"/api/share/{body['token']}/download", headers=JSON).status_code == 410
    with app.app_context():
        assert share_row(body["token"]).downloads == 0


# -- one-time --------------------------------------------------------------
def test_one_time_first_download_succeeds_second_fails(fresh_client, make_share):
    body = make_share(content=b"single use payload", one_time="true")

    first = fresh_client.get(f"/api/share/{body['token']}/download")
    assert first.status_code == 200
    assert first.data == b"single use payload"

    second = fresh_client.get(f"/api/share/{body['token']}/download", headers=JSON)
    assert second.status_code == 410
    assert second.get_json()["code"] == "used"


def test_one_time_receiver_page_shows_used_state(fresh_client, make_share):
    body = make_share(one_time="true")
    fresh_client.get(f"/api/share/{body['token']}/download")
    page = fresh_client.get(f"/s/{body['token']}").get_data(as_text=True)
    assert "Already used" in page
    assert "Download file" not in page


def test_non_one_time_share_allows_repeat_downloads(fresh_client, make_share):
    body = make_share(one_time="false")
    for _ in range(3):
        assert fresh_client.get(f"/api/share/{body['token']}/download").status_code == 200


def test_concurrent_one_time_downloads_consume_exactly_once(app, make_share):
    """Two requests racing for the same one-time link: exactly one wins.

    Each thread gets its own test client and therefore its own request context
    and database connection, so this exercises the real conditional UPDATE
    rather than a single-threaded illusion.
    """
    body = make_share(content=b"only once", one_time="true")
    token = body["token"]
    results: list[int] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def attempt() -> None:
        client = app.test_client()
        barrier.wait(timeout=10)
        try:
            response = client.get(f"/api/share/{token}/download", headers=JSON)
            status = response.status_code
            response.close()
        except sqlite3.OperationalError:
            # SQLite may surface a lock contention error under this much
            # concurrency; that is a refusal, not a second successful serve.
            status = 503
        with lock:
            results.append(status)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert len(results) == 8
    assert results.count(200) == 1, f"expected exactly one success, got {results}"

    with app.app_context():
        share = share_row(token)
        assert share.used is True
        assert share.downloads == 1


# -- missing data ----------------------------------------------------------
def test_missing_blob_is_reported_without_consuming_the_share(fresh_client, make_share, app, storage_dir):
    body = make_share(one_time="true")
    for blob in storage_dir.iterdir():
        blob.unlink()

    response = fresh_client.get(f"/api/share/{body['token']}/download", headers=JSON)
    assert response.status_code == 410
    with app.app_context():
        share = share_row(body["token"])
        assert share.downloads == 0
        assert share.used is False


# -- auditing --------------------------------------------------------------
def test_successful_download_is_audited(fresh_client, make_share, app):
    body = make_share()
    fresh_client.get(f"/api/share/{body['token']}/download")
    with app.app_context():
        share = share_row(body["token"])
        events = [
            row.event_type
            for row in db.session.query(AuditLog).filter(AuditLog.share_id == share.id)
        ]
        assert "DOWNLOAD_ATTEMPT" in events
        assert "DOWNLOAD_SUCCESS" in events


def test_consumed_one_time_share_is_audited_as_consumed(fresh_client, make_share, app):
    body = make_share(one_time="true")
    fresh_client.get(f"/api/share/{body['token']}/download")
    with app.app_context():
        share = share_row(body["token"])
        events = [
            row.event_type
            for row in db.session.query(AuditLog).filter(AuditLog.share_id == share.id)
        ]
        assert "SHARE_CONSUMED" in events


def test_failed_download_is_audited_with_a_reason(fresh_client, make_share, app):
    body = make_share()
    with app.app_context():
        share = share_row(body["token"])
        share.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()
    fresh_client.get(f"/api/share/{body['token']}/download", headers=JSON)
    with app.app_context():
        share = share_row(body["token"])
        rows = db.session.query(AuditLog).filter(
            AuditLog.share_id == share.id, AuditLog.event_type == "DOWNLOAD_FAILED"
        ).all()
        assert rows and rows[0].reason == "expired"
        assert rows[0].success is False
