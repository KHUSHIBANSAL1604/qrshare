"""S3 backend driven through the real boto3 client.

`test_storage_s3.py` uses an injected stub, which proves the framing and key
handling but never exercises boto3 itself. These tests run the genuine client
-- signing, `upload_fileobj`, real multipart assembly, botocore's
`StreamingBody` -- against an in-process mock S3, so the code path that runs
in production is the code path under test.

Skipped automatically if moto is not installed, since it is a dev-only
dependency and must not become a deployment requirement.
"""
from __future__ import annotations

import io
import os

import pytest

moto = pytest.importorskip("moto", reason="moto is a development-only dependency")

from moto import mock_aws  # noqa: E402

from app.services.encryption_service import EncryptionService  # noqa: E402
from app.services.storage import S3StorageBackend, StorageError  # noqa: E402
from app.services.storage import s3 as s3_module  # noqa: E402

BUCKET = "qrshare-integration"


@pytest.fixture
def aws_credentials(monkeypatch):
    """Keep boto3 from picking up real credentials or hitting the network."""
    for name, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
    }.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def backend(aws_credentials):
    with mock_aws():
        import boto3

        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=BUCKET)
        # No `client=` argument: this constructs a genuine boto3 client, the
        # same way build_storage does in production.
        yield S3StorageBackend(
            BUCKET,
            access_key="testing",
            secret_key="testing",
            region="us-east-1",
            prefix="blobs",
        )


def test_real_client_round_trip(backend):
    key = backend.new_key()
    payload = os.urandom(2048)
    assert backend.save(key, iter([payload])) == len(payload)
    assert backend.open(key).read(-1) == payload


def test_real_client_exists_and_delete(backend):
    key = backend.new_key()
    assert backend.exists(key) is False
    backend.save(key, iter([b"data"]))
    assert backend.exists(key) is True
    assert backend.delete(key) is True
    assert backend.exists(key) is False


def test_missing_object_raises_storage_error(backend):
    with pytest.raises(StorageError):
        backend.open(backend.new_key())


def test_real_multipart_upload_reassembles_correctly(backend, monkeypatch):
    """Files past the multipart threshold are uploaded in parts.

    A bug in the iterator-to-file adapter shows up here and nowhere else:
    boto3 calls read() repeatedly with its own sizes across part boundaries,
    and a mistake silently drops or duplicates bytes.
    """
    monkeypatch.setattr(s3_module, "MULTIPART_CHUNK", 1024 * 1024)
    payload = os.urandom(5 * 1024 * 1024 + 7777)  # forces several parts
    key = backend.new_key()

    written = backend.save(key, iter([payload[i : i + 64 * 1024] for i in range(0, len(payload), 64 * 1024)]))
    assert written == len(payload)
    assert backend.open(key).read(-1) == payload


def test_encrypted_blob_survives_a_real_multipart_round_trip(backend, monkeypatch):
    """The end-to-end property that matters: a large encrypted file written
    through real multipart must decrypt back byte-for-byte."""
    monkeypatch.setattr(s3_module, "MULTIPART_CHUNK", 1024 * 1024)
    service = EncryptionService(b"\x0b" * 32, chunk_size=256 * 1024)
    file_key = service.generate_file_key()
    plaintext = os.urandom(4 * 1024 * 1024 + 123)

    key = backend.new_key()
    backend.save(key, service.encrypt_stream(io.BytesIO(plaintext), file_key))

    handle = backend.open(key)
    assert service.decrypt_to_bytes(handle, file_key) == plaintext


def test_streaming_body_short_reads_are_handled_by_the_real_client(backend):
    """botocore may return fewer bytes than requested; read(n) must not."""
    payload = os.urandom(300 * 1024)
    key = backend.new_key()
    backend.save(key, iter([payload]))

    handle = backend.open(key)
    first = handle.read(200 * 1024)
    assert len(first) == 200 * 1024
    assert first == payload[: 200 * 1024]
    assert handle.read(100 * 1024) == payload[200 * 1024 :]


def test_list_keys_against_the_real_client(backend):
    keys = sorted(backend.new_key() for _ in range(3))
    for key in keys:
        backend.save(key, iter([b"x"]))
    # An object that is not ours must not be reported as a storage key.
    import boto3

    boto3.client("s3", region_name="us-east-1").put_object(
        Bucket=BUCKET, Key="blobs/readme.txt", Body=b"not a blob"
    )
    assert sorted(backend.list_keys()) == keys


def test_empty_file_round_trips(backend):
    """A zero-byte upload still produces one authenticated frame."""
    service = EncryptionService(b"\x0c" * 32, chunk_size=1024)
    file_key = service.generate_file_key()
    key = backend.new_key()
    backend.save(key, service.encrypt_stream(io.BytesIO(b""), file_key))
    assert service.decrypt_to_bytes(backend.open(key), file_key) == b""


def test_upload_failure_surfaces_as_storage_error(aws_credentials):
    """Writing to a bucket that does not exist must raise StorageError, not a
    raw botocore exception that would reach the user as a 500."""
    with mock_aws():
        backend = S3StorageBackend(
            "no-such-bucket", access_key="testing", secret_key="testing", region="us-east-1"
        )
        with pytest.raises(StorageError):
            backend.save(backend.new_key(), iter([b"data"]))
