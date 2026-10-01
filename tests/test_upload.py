"""Upload endpoint: validation, storage, and metadata handling."""
from __future__ import annotations

import io

from conftest import upload_payload

from app.extensions import db
from app.models import AuditLog, Share, StoredFile


def post(client, **kwargs):
    return client.post(
        "/api/upload", data=upload_payload(**kwargs), content_type="multipart/form-data"
    )


def test_valid_upload_creates_a_share(client, app):
    response = post(client, content=b"hello world", filename="notes.txt")
    assert response.status_code == 201

    body = response.get_json()
    assert body["ok"] is True
    assert body["filename"] == "notes.txt"
    assert body["size"] == 11
    assert body["status"] == "active"
    assert body["password_protected"] is False
    assert body["one_time"] is False
    assert body["share_url"].endswith("/s/" + body["token"])

    with app.app_context():
        assert db.session.query(StoredFile).count() == 1
        assert db.session.query(Share).count() == 1


def test_upload_writes_an_encrypted_blob_not_the_plaintext(client, storage_dir):
    secret = b"PLAINTEXT-CANARY-8842" * 40
    assert post(client, content=secret, filename="secret.bin").status_code == 201

    blobs = list(storage_dir.iterdir())
    assert len(blobs) == 1
    data = blobs[0].read_bytes()
    assert b"PLAINTEXT-CANARY" not in data
    assert data.startswith(b"QRS1")


def test_stored_filename_is_random_not_the_original(client, app):
    post(client, content=b"x", filename="my-private-report.pdf")
    with app.app_context():
        record = db.session.query(StoredFile).one()
        assert record.original_filename == "my-private-report.pdf"
        assert "my-private-report" not in record.stored_filename
        assert record.stored_filename.endswith(".enc")
        assert len(record.stored_filename) > 20


def test_file_key_is_stored_wrapped_not_in_the_clear(client, app, services):
    post(client, content=b"x", filename="a.txt")
    with app.app_context():
        record = db.session.query(StoredFile).one()
        # It must decrypt under the master key and be a valid 32-byte key.
        import base64

        key = services.encryption.unwrap_key(base64.b64decode(record.encrypted_file_key))
        assert len(key) == 32
        # ...and it must not simply be sitting there base64'd in the clear.
        assert base64.b64decode(record.encrypted_file_key) != key


def test_empty_file_is_rejected(client):
    response = post(client, content=b"", filename="empty.txt")
    assert response.status_code == 400
    assert "empty" in response.get_json()["error"].lower()


def test_missing_file_is_rejected(client):
    response = client.post("/api/upload", data={}, content_type="multipart/form-data")
    assert response.status_code == 400


def test_oversized_file_is_rejected(client, app):
    too_big = b"a" * (app.config["MAX_CONTENT_LENGTH"] + 1024)
    response = client.post(
        "/api/upload",
        data={"file": (io.BytesIO(too_big), "big.bin")},
        content_type="multipart/form-data",
    )
    # Werkzeug aborts with 413 once the body exceeds MAX_CONTENT_LENGTH.
    assert response.status_code in (400, 413)


def test_blocked_extension_is_rejected(client, storage_dir):
    response = post(client, content=b"MZ\x90\x00", filename="payload.exe")
    assert response.status_code == 400
    assert "executable" in response.get_json()["error"].lower()
    assert not list(storage_dir.iterdir())


def test_nothing_is_persisted_when_validation_fails(client, app):
    post(client, content=b"", filename="empty.txt")
    with app.app_context():
        assert db.session.query(StoredFile).count() == 0
        assert db.session.query(Share).count() == 0


def test_expiry_is_honoured(client, app):
    body = post(client, expiry_minutes="10")
    assert body.status_code == 201
    from datetime import datetime, timedelta, timezone

    token = body.get_json()["token"]
    with app.app_context():
        share = db.session.query(Share).filter(Share.token == token).one()
        expected = datetime.now(timezone.utc) + timedelta(minutes=10)
        assert abs((share.expires_at_utc - expected).total_seconds()) < 30


def test_out_of_range_expiry_is_rejected(client, app):
    response = post(client, expiry_minutes=str(app.config["MAX_EXPIRY_MINUTES"] + 1))
    assert response.status_code == 400


def test_non_numeric_expiry_is_rejected(client):
    assert post(client, expiry_minutes="not-a-number").status_code == 400


def test_password_options_are_validated(client):
    short = post(client, password_protect="true", password="abc", password_confirm="abc")
    assert short.status_code == 400

    mismatch = post(
        client, password_protect="true", password="longenough", password_confirm="different"
    )
    assert mismatch.status_code == 400


def test_password_is_hashed_not_stored(client, app):
    body = post(client, password_protect="true", password="hunter2!", password_confirm="hunter2!")
    token = body.get_json()["token"]
    with app.app_context():
        share = db.session.query(Share).filter(Share.token == token).one()
        assert share.password_hash
        assert "hunter2!" not in share.password_hash
        assert share.password_hash.startswith(("$argon2", "scrypt:"))


def test_one_time_flag_is_recorded(client):
    assert post(client, one_time="true").get_json()["one_time"] is True
    assert post(client).get_json()["one_time"] is False


def test_upload_is_audited(client, app):
    token = post(client).get_json()["token"]
    with app.app_context():
        share = db.session.query(Share).filter(Share.token == token).one()
        events = {
            row.event_type
            for row in db.session.query(AuditLog).filter(AuditLog.share_id == share.id)
        }
        assert {"FILE_UPLOADED", "SHARE_CREATED"} <= events


def test_audit_log_never_contains_the_password(client, app):
    post(client, password_protect="true", password="SuperSecret1", password_confirm="SuperSecret1")
    with app.app_context():
        for row in db.session.query(AuditLog).all():
            assert "SuperSecret1" not in (row.reason or "")
            assert "SuperSecret1" not in (row.user_agent or "")
