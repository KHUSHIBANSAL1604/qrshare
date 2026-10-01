"""Object storage backend for S3-compatible services.

Works with AWS S3, Cloudflare R2, Backblaze B2 and MinIO -- anything that
speaks the S3 API -- by pointing ``S3_ENDPOINT_URL`` at the right host.

This exists because a container filesystem is not durable: Render (and most
PaaS hosts) give each deploy a fresh disk, so blobs written locally vanish on
the next restart. The encrypted bytes have to live somewhere that outlives the
process.

Nothing about the encryption changes. Objects stored here are the same
authenticated AES-256-GCM frames the local backend writes; the provider only
ever sees ciphertext, and the key that would decrypt it never leaves the
server's own configuration.
"""
from __future__ import annotations

import io
import logging
from typing import BinaryIO, Iterator

from app.services.storage.base import StorageBackend, StorageError
from app.services.storage.local import KEY_PATTERN

logger = logging.getLogger(__name__)

#: 8 MiB parts: comfortably above S3's 5 MiB minimum, small enough that a
#: multipart upload of a 100 MB file stays well inside container memory.
MULTIPART_CHUNK = 8 * 1024 * 1024


class _IteratorStream(io.RawIOBase):
    """Presents an iterator of byte chunks as a readable file object.

    ``boto3.upload_fileobj`` wants something with ``read()``; the encryption
    service produces a generator. This adapts one to the other without ever
    materialising the whole file.
    """

    def __init__(self, chunks: Iterator[bytes]) -> None:
        self._chunks = iter(chunks)
        self._buffer = b""
        self.bytes_read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, target) -> int:  # type: ignore[override]
        while not self._buffer:
            try:
                self._buffer = next(self._chunks)
            except StopIteration:
                return 0
        count = min(len(target), len(self._buffer))
        target[:count] = self._buffer[:count]
        self._buffer = self._buffer[count:]
        self.bytes_read += count
        return count


class _ExactReader:
    """Wraps a botocore streaming body so ``read(n)`` returns exactly n bytes.

    ``StreamingBody.read(n)`` is allowed to come up short when the underlying
    socket hands over a partial chunk. The decryption framing calls
    ``read(exact_length)`` and treats a short read as a truncated blob, so
    without this loop a perfectly good file would intermittently fail its
    integrity check.
    """

    def __init__(self, body) -> None:
        self._body = body

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            return self._body.read()
        out = bytearray()
        while len(out) < size:
            chunk = self._body.read(size - len(out))
            if not chunk:
                break
            out.extend(chunk)
        return bytes(out)

    def close(self) -> None:
        try:
            self._body.close()
        except Exception:  # noqa: BLE001 - closing must never raise upward
            logger.debug("ignored an error while closing an S3 body")


class S3StorageBackend(StorageBackend):
    """Stores each encrypted blob as one object under an optional prefix."""

    name = "s3"

    def __init__(
        self,
        bucket: str,
        *,
        endpoint_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        region: str = "auto",
        prefix: str = "",
        client=None,
    ) -> None:
        if not bucket:
            raise StorageError("S3_BUCKET is required when STORAGE_BACKEND=s3")

        self.bucket = bucket
        self.prefix = prefix.strip("/") + "/" if prefix.strip("/") else ""

        # An injected client keeps the tests honest: they exercise the real
        # framing, key validation and short-read handling against a stub
        # rather than needing network access to a live bucket.
        if client is not None:
            self._client = client
            return

        try:
            import boto3
            from botocore.config import Config as BotoConfig
        except ImportError as exc:  # pragma: no cover - depends on install
            raise StorageError(
                "boto3 is required for the S3 storage backend; add it to requirements.txt"
            ) from exc

        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url or None,
            aws_access_key_id=access_key or None,
            aws_secret_access_key=secret_key or None,
            region_name=region,
            # Retry a few times: object storage occasionally returns a
            # transient 5xx, and losing a share to that would be unnecessary.
            config=BotoConfig(
                retries={"max_attempts": 3, "mode": "standard"},
                signature_version="s3v4",
            ),
        )

    # -- key safety --------------------------------------------------------
    def _object_key(self, key: str) -> str:
        """Validate and namespace a storage key.

        The same strict allowlist the local backend uses. An object store has
        no parent directory to escape to, but a key is still attacker-adjacent
        input and a predictable shape keeps ``list_keys`` honest.
        """
        if not isinstance(key, str) or not KEY_PATTERN.match(key):
            raise StorageError("invalid storage key")
        return self.prefix + key

    # -- interface ---------------------------------------------------------
    def save(self, key: str, chunks: Iterator[bytes]) -> int:
        from boto3.s3.transfer import TransferConfig

        object_key = self._object_key(key)
        stream = _IteratorStream(chunks)
        try:
            self._client.upload_fileobj(
                io.BufferedReader(stream, buffer_size=MULTIPART_CHUNK),
                self.bucket,
                object_key,
                ExtraArgs={"ContentType": "application/octet-stream"},
                Config=TransferConfig(
                    multipart_threshold=MULTIPART_CHUNK,
                    multipart_chunksize=MULTIPART_CHUNK,
                    # Sequential: the source is a generator and cannot be
                    # read from several threads at once.
                    use_threads=False,
                ),
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a storage failure
            logger.exception("S3 upload failed")
            raise StorageError("could not store the object") from exc
        return stream.bytes_read

    def open(self, key: str) -> BinaryIO:
        object_key = self._object_key(key)
        try:
            response = self._client.get_object(Bucket=self.bucket, Key=object_key)
        except Exception as exc:  # noqa: BLE001
            raise StorageError("stored object is missing") from exc
        return _ExactReader(response["Body"])  # type: ignore[return-value]

    def delete(self, key: str) -> bool:
        try:
            object_key = self._object_key(key)
        except StorageError:
            logger.warning("refused to delete an invalid storage key")
            return False
        if not self.exists(key):
            return False
        try:
            self._client.delete_object(Bucket=self.bucket, Key=object_key)
            return True
        except Exception:  # noqa: BLE001
            logger.exception("S3 delete failed")
            return False

    def exists(self, key: str) -> bool:
        try:
            object_key = self._object_key(key)
        except StorageError:
            return False
        try:
            self._client.head_object(Bucket=self.bucket, Key=object_key)
            return True
        except Exception:  # noqa: BLE001 - 404 and access errors both mean "no"
            return False

    def list_keys(self) -> Iterator[str]:
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for item in page.get("Contents", []):
                name = item["Key"][len(self.prefix) :]
                if KEY_PATTERN.match(name):
                    yield name
