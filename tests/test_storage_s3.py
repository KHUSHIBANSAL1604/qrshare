"""S3 storage backend.

Exercised against an in-memory stub rather than a live bucket, so the suite
stays offline and deterministic. The stub deliberately reproduces the two
S3 behaviours that break naive clients: ``read(n)`` returning fewer than ``n``
bytes, and a missing object raising rather than returning ``None``.
"""
from __future__ import annotations

import io
import os

import pytest

from app.services.encryption_service import EncryptionService
from app.services.storage import S3StorageBackend, StorageError


class _ShortReadBody:
    """A streaming body that hands back at most 7 bytes per read().

    Botocore makes no promise that ``read(n)`` returns n bytes; a real socket
    routinely comes up short. Anything that assumes otherwise corrupts large
    downloads intermittently, which is the worst kind of bug to ship.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            chunk = self._data[self._pos :]
            self._pos = len(self._data)
            return chunk
        end = min(self._pos + min(size, 7), len(self._data))
        chunk = self._data[self._pos : end]
        self._pos = end
        return chunk

    def close(self) -> None:
        self.closed = True


class FakeS3Client:
    """Minimal in-memory stand-in for the boto3 S3 client."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def upload_fileobj(self, fileobj, bucket, key, ExtraArgs=None, Config=None):  # noqa: N803
        self.objects[key] = fileobj.read()

    def get_object(self, Bucket, Key):  # noqa: N803
        if Key not in self.objects:
            raise KeyError(f"NoSuchKey: {Key}")
        return {"Body": _ShortReadBody(self.objects[Key])}

    def head_object(self, Bucket, Key):  # noqa: N803
        if Key not in self.objects:
            raise KeyError(f"404: {Key}")
        return {"ContentLength": len(self.objects[Key])}

    def delete_object(self, Bucket, Key):  # noqa: N803
        self.objects.pop(Key, None)

    def get_paginator(self, name):
        client = self

        class _Paginator:
            def paginate(self, Bucket, Prefix=""):  # noqa: N803
                yield {
                    "Contents": [
                        {"Key": k} for k in sorted(client.objects) if k.startswith(Prefix)
                    ]
                }

        return _Paginator()


@pytest.fixture
def fake_client():
    return FakeS3Client()


@pytest.fixture
def backend(fake_client):
    return S3StorageBackend("test-bucket", prefix="blobs", client=fake_client)


def valid_key(backend: S3StorageBackend) -> str:
    return backend.new_key()


# -- round trip ------------------------------------------------------------
def test_save_and_open_round_trip(backend):
    key = valid_key(backend)
    written = backend.save(key, iter([b"hello ", b"object ", b"storage"]))
    assert written == len(b"hello object storage")
    with_handle = backend.open(key)
    assert with_handle.read(-1) == b"hello object storage"


def test_short_reads_are_absorbed(backend):
    """read(n) must return exactly n bytes even when the body dribbles."""
    payload = os.urandom(500)
    key = valid_key(backend)
    backend.save(key, iter([payload]))
    handle = backend.open(key)
    assert len(handle.read(300)) == 300  # stub would otherwise return 7
    assert len(handle.read(200)) == 200
    assert handle.read(10) == b""


def test_encrypted_blob_survives_the_round_trip(backend):
    """The real payload: framed AES-GCM through S3 and back out again."""
    service = EncryptionService(b"\x07" * 32, chunk_size=64)
    file_key = service.generate_file_key()
    plaintext = os.urandom(4096)

    key = valid_key(backend)
    backend.save(key, service.encrypt_stream(io.BytesIO(plaintext), file_key))

    handle = backend.open(key)
    assert service.decrypt_to_bytes(handle, file_key) == plaintext


def test_stored_object_is_ciphertext_not_plaintext(backend, fake_client):
    service = EncryptionService(b"\x07" * 32, chunk_size=64)
    secret = b"OBJECT-STORE-CANARY" * 30
    key = valid_key(backend)
    backend.save(key, service.encrypt_stream(io.BytesIO(secret), service.generate_file_key()))

    stored = next(iter(fake_client.objects.values()))
    assert b"OBJECT-STORE-CANARY" not in stored
    assert stored.startswith(b"QRS1")


def test_iterator_is_streamed_not_buffered(backend):
    """The adapter must pull from the generator lazily, not drain it first."""
    pulled = []

    def chunks():
        for i in range(8):
            pulled.append(i)
            yield b"x" * 1024

    backend.save(valid_key(backend), chunks())
    assert pulled == list(range(8))


# -- key handling ----------------------------------------------------------
def test_keys_are_namespaced_by_prefix(backend, fake_client):
    key = valid_key(backend)
    backend.save(key, iter([b"data"]))
    assert list(fake_client.objects) == [f"blobs/{key}"]


@pytest.mark.parametrize(
    "bad", ["../escape.enc", "sub/dir.enc", "no-extension", "/abs.enc", "..\\win.enc", ""]
)
def test_crafted_keys_are_rejected(backend, bad):
    with pytest.raises(StorageError):
        backend.open(bad)
    assert backend.exists(bad) is False
    assert backend.delete(bad) is False


def test_list_keys_strips_the_prefix_and_filters_foreign_objects(backend, fake_client):
    key = valid_key(backend)
    backend.save(key, iter([b"ours"]))
    fake_client.objects["blobs/not-ours.txt"] = b"someone else"
    fake_client.objects["other-prefix/thing.enc"] = b"not ours either"
    assert list(backend.list_keys()) == [key]


# -- absence and deletion --------------------------------------------------
def test_missing_object_raises_on_open(backend):
    with pytest.raises(StorageError):
        backend.open(valid_key(backend))


def test_exists_and_delete(backend):
    key = valid_key(backend)
    assert backend.exists(key) is False
    backend.save(key, iter([b"data"]))
    assert backend.exists(key) is True
    assert backend.delete(key) is True
    assert backend.exists(key) is False
    assert backend.delete(key) is False  # already gone


def test_empty_bucket_name_is_rejected():
    with pytest.raises(StorageError):
        S3StorageBackend("", client=FakeS3Client())


# -- backend selection -----------------------------------------------------
def test_app_builds_the_s3_backend_from_config(app, monkeypatch):
    """STORAGE_BACKEND=s3 must produce an S3 backend, not a local one."""
    from app.services import build_storage

    created = {}

    class _Spy(FakeS3Client):
        pass

    import app.services as services_module

    def fake_s3(bucket, **kwargs):
        created["bucket"] = bucket
        created.update(kwargs)
        return S3StorageBackend(bucket, client=_Spy())

    monkeypatch.setattr(services_module, "S3StorageBackend", fake_s3)
    app.config.update(
        STORAGE_BACKEND="s3",
        S3_BUCKET="qrshare-prod",
        S3_ENDPOINT_URL="https://example.r2.cloudflarestorage.com",
        S3_ACCESS_KEY_ID="key-id",
        S3_SECRET_ACCESS_KEY="secret",
        S3_REGION="auto",
        S3_PREFIX="blobs",
    )
    backend = build_storage(app)
    assert backend.name == "s3"
    assert created["bucket"] == "qrshare-prod"
    assert created["endpoint_url"].endswith("cloudflarestorage.com")


def test_unknown_backend_name_fails_loudly(app):
    from app.services import build_storage

    app.config["STORAGE_BACKEND"] = "dropbox"
    with pytest.raises(RuntimeError, match="unknown STORAGE_BACKEND"):
        build_storage(app)


def test_local_remains_the_default(app):
    from app.services import build_storage

    assert build_storage(app).name == "local"
