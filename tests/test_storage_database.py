"""Database storage backend.

Runs against SQLite, which exercises the same SQLAlchemy Core path used
against Postgres in production: identical table definition, identical chunked
reads and writes. The dialect differs; the code under test does not.
"""
from __future__ import annotations

import io
import os

import pytest

from app.services.encryption_service import EncryptionService
from app.services.storage import DatabaseStorageBackend, StorageError


@pytest.fixture
def url(tmp_path):
    return f"sqlite:///{(tmp_path / 'blobs.db').as_posix()}"


@pytest.fixture
def backend(url):
    # A small chunk size so multi-row behaviour shows up with small inputs.
    return DatabaseStorageBackend(url, chunk_size=256)


# -- round trip ------------------------------------------------------------
@pytest.mark.parametrize("size", [0, 1, 255, 256, 257, 1024, 5000])
def test_round_trip_across_chunk_boundaries(backend, size):
    payload = os.urandom(size)
    key = backend.new_key()
    assert backend.save(key, iter([payload])) == size
    with backend.open(key) as handle:
        assert handle.read(-1) == payload


def test_exact_reads_span_row_boundaries(backend):
    """read(n) must return exactly n bytes even when n crosses several rows."""
    payload = os.urandom(2000)  # ~8 rows at chunk_size=256
    key = backend.new_key()
    backend.save(key, iter([payload]))

    handle = backend.open(key)
    assert handle.read(700) == payload[:700]
    assert handle.read(1000) == payload[700:1700]
    assert handle.read(500) == payload[1700:]
    assert handle.read(10) == b""
    handle.close()


def test_input_chunking_does_not_change_the_result(backend):
    """However the producer slices its output, the stored bytes are the same."""
    payload = os.urandom(1500)
    stored = []
    for piece in (1, 7, 256, 999):
        key = backend.new_key()
        backend.save(key, iter([payload[i : i + piece] for i in range(0, len(payload), piece)]))
        with backend.open(key) as handle:
            stored.append(handle.read(-1))
    assert all(blob == payload for blob in stored)


def test_encrypted_blob_round_trip(backend):
    """The real payload: framed AES-GCM through the database and back."""
    service = EncryptionService(b"\x0e" * 32, chunk_size=128)
    file_key = service.generate_file_key()
    plaintext = os.urandom(4096)

    key = backend.new_key()
    backend.save(key, service.encrypt_stream(io.BytesIO(plaintext), file_key))
    with backend.open(key) as handle:
        assert service.decrypt_to_bytes(handle, file_key) == plaintext


def test_stored_rows_are_ciphertext(backend, url):
    from sqlalchemy import create_engine, text

    service = EncryptionService(b"\x0e" * 32, chunk_size=128)
    secret = b"DATABASE-STORE-CANARY" * 40
    key = backend.new_key()
    backend.save(key, service.encrypt_stream(io.BytesIO(secret), service.generate_file_key()))

    with create_engine(url).connect() as connection:
        blob = b"".join(
            row[0]
            for row in connection.execute(
                text("SELECT data FROM blob_chunks ORDER BY seq")
            ).fetchall()
        )
    assert b"DATABASE-STORE-CANARY" not in blob
    assert blob.startswith(b"QRS1")


def test_large_blob_is_chunked_not_one_row(backend, url):
    from sqlalchemy import create_engine, text

    key = backend.new_key()
    backend.save(key, iter([os.urandom(4096)]))
    with create_engine(url).connect() as connection:
        rows = connection.execute(
            text("SELECT COUNT(*) FROM blob_chunks WHERE storage_key = :k"), {"k": key}
        ).scalar()
    assert rows == 16  # 4096 / 256


def test_writes_stream_rather_than_buffering(backend):
    pulled = []

    def chunks():
        for i in range(10):
            pulled.append(i)
            yield b"x" * 256

    backend.save(backend.new_key(), chunks())
    assert pulled == list(range(10))


# -- absence, deletion, listing --------------------------------------------
def test_missing_blob_raises_on_open(backend):
    with pytest.raises(StorageError):
        backend.open(backend.new_key())


def test_exists_and_delete(backend):
    key = backend.new_key()
    assert backend.exists(key) is False
    backend.save(key, iter([b"data"]))
    assert backend.exists(key) is True
    assert backend.delete(key) is True
    assert backend.exists(key) is False
    assert backend.delete(key) is False


def test_delete_removes_every_row(backend, url):
    from sqlalchemy import create_engine, text

    key = backend.new_key()
    backend.save(key, iter([os.urandom(2048)]))
    backend.delete(key)
    with create_engine(url).connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM blob_chunks")).scalar() == 0


def test_list_keys_is_deduplicated(backend):
    keys = sorted(backend.new_key() for _ in range(3))
    for key in keys:
        backend.save(key, iter([os.urandom(1000)]))  # several rows each
    assert sorted(backend.list_keys()) == keys


def test_total_bytes_tracks_usage(backend):
    assert backend.total_bytes() == 0
    backend.save(backend.new_key(), iter([b"a" * 1000]))
    backend.save(backend.new_key(), iter([b"b" * 500]))
    assert backend.total_bytes() == 1500


def test_blobs_are_isolated_from_each_other(backend):
    first, second = backend.new_key(), backend.new_key()
    backend.save(first, iter([b"first blob"]))
    backend.save(second, iter([b"second blob"]))
    with backend.open(first) as handle:
        assert handle.read(-1) == b"first blob"
    backend.delete(first)
    with backend.open(second) as handle:
        assert handle.read(-1) == b"second blob"


# -- key validation --------------------------------------------------------
@pytest.mark.parametrize("bad", ["../escape.enc", "sub/dir.enc", "no-extension", "", "/abs.enc"])
def test_crafted_keys_are_rejected(backend, bad):
    with pytest.raises(StorageError):
        backend.open(bad)
    assert backend.exists(bad) is False
    assert backend.delete(bad) is False


def test_empty_url_is_rejected():
    with pytest.raises(StorageError):
        DatabaseStorageBackend("")


# -- backend selection ------------------------------------------------------
def test_app_selects_the_database_backend(app):
    from app.services import build_storage

    app.config["STORAGE_BACKEND"] = "database"
    assert build_storage(app).name == "database"


def test_unknown_backend_names_still_fail_loudly(app):
    from app.services import build_storage

    app.config["STORAGE_BACKEND"] = "ftp"
    with pytest.raises(RuntimeError, match="unknown STORAGE_BACKEND"):
        build_storage(app)


# -- the whole application running on database storage ----------------------
@pytest.fixture
def db_app(tmp_path):
    """An app configured exactly as the free production deployment is."""
    from app import create_app
    from app.extensions import db as _db

    application = create_app(
        "testing",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{(tmp_path / 'app.db').as_posix()}",
        STORAGE_BACKEND="database",
    )
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()


def test_full_share_flow_on_database_storage(db_app):
    """Upload, QR, password, download, one-time refusal -- with every byte
    living in the database rather than on disk."""
    sender, receiver = db_app.test_client(), db_app.test_client()
    payload = b"%PDF database-backed share\n" * 400
    password = "db-backed-pass"

    created = sender.post(
        "/api/upload",
        data={
            "file": (io.BytesIO(payload), "report.pdf"),
            "expiry_minutes": "10",
            "one_time": "true",
            "password_protect": "true",
            "password": password,
            "password_confirm": password,
        },
        content_type="multipart/form-data",
    )
    assert created.status_code == 201, created.get_data(as_text=True)
    token = created.get_json()["token"]

    assert db_app.extensions["qrshare"].storage.name == "database"
    assert db_app.extensions["qrshare"].storage.total_bytes() > len(payload)

    page = receiver.get(f"/s/{token}")
    assert b"Enter the password" in page.data

    refused = receiver.get(f"/api/share/{token}/download", headers={"Accept": "application/json"})
    assert refused.status_code == 401

    ticket = receiver.post(
        f"/api/share/{token}/verify-password", json={"password": password}
    ).get_json()["ticket"]

    got = receiver.get(f"/api/share/{token}/download?ticket={ticket}")
    assert got.status_code == 200
    assert got.data == payload  # decrypted straight out of the database

    again = receiver.get(
        f"/api/share/{token}/download?ticket={ticket}", headers={"Accept": "application/json"}
    )
    assert again.status_code == 410
    assert again.get_json()["code"] == "used"


def test_cleanup_frees_database_space(db_app):
    """Expired shares must actually release their rows, since a free database
    is small and anything that leaks would fill it."""
    from datetime import datetime, timedelta, timezone

    from app.extensions import db as _db
    from app.models import Share

    client = db_app.test_client()
    client.post(
        "/api/upload",
        data={"file": (io.BytesIO(b"z" * 50_000), "big.bin"), "expiry_minutes": "10"},
        content_type="multipart/form-data",
    )
    storage = db_app.extensions["qrshare"].storage
    assert storage.total_bytes() > 50_000

    share = _db.session.query(Share).one()
    share.expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
    _db.session.commit()

    db_app.extensions["qrshare"].cleanup.run()
    assert storage.total_bytes() == 0
