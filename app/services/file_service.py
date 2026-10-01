"""Turns an incoming upload into an encrypted blob plus a metadata row."""
from __future__ import annotations

import base64
import logging
from typing import BinaryIO

from app.extensions import db
from app.models import StoredFile
from app.services.encryption_service import DecryptionError, EncryptionService
from app.services.storage import StorageBackend, StorageError
from app.utils.validation import FileMeta

logger = logging.getLogger(__name__)


def stream_size(stream: BinaryIO) -> int:
    """Length of a seekable upload stream, leaving the cursor at the start."""
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(0)
    return size


class FileService:
    """Encrypt-on-write / decrypt-on-read wrapper around a storage backend."""

    def __init__(self, storage: StorageBackend, encryption: EncryptionService) -> None:
        self.storage = storage
        self.encryption = encryption

    # -- write path --------------------------------------------------------
    def store(self, stream: BinaryIO, meta: FileMeta, size: int) -> StoredFile:
        """Encrypt ``stream`` and persist it.

        The row is added to the session but **not** committed; the caller
        commits once the share has been created too, so a failure never leaves
        an orphaned file row behind.
        """
        file_key = self.encryption.generate_file_key()
        key = self.storage.new_key()
        try:
            self.storage.save(key, self.encryption.encrypt_stream(stream, file_key))
        except StorageError:
            logger.exception("storage rejected an upload")
            raise
        except Exception:
            # Never leave a partial blob behind if encryption blew up.
            self.storage.delete(key)
            raise

        record = StoredFile(
            original_filename=meta.display_name,
            stored_filename=key,
            storage_backend=self.storage.name,
            mime_type=meta.mime_type,
            size=size,
            encrypted_file_key=base64.b64encode(self.encryption.wrap_key(file_key)).decode(),
        )
        db.session.add(record)
        return record

    # -- read path ---------------------------------------------------------
    def open_plaintext(self, record: StoredFile):
        """Yield decrypted chunks of ``record``.

        The generator owns the file handle and closes it on exhaustion or
        error, which matters because Flask consumes it after the request
        context has already been torn down.
        """
        wrapped = base64.b64decode(record.encrypted_file_key)
        file_key = self.encryption.unwrap_key(wrapped)
        handle = self.storage.open(record.stored_filename)

        def generate():
            try:
                yield from self.encryption.decrypt_stream(handle, file_key)
            except DecryptionError:
                # Stop the stream rather than emit unauthenticated bytes. The
                # client sees a truncated download; the reason is logged here.
                logger.exception("decryption failed for a stored file")
                raise
            finally:
                handle.close()

        return generate()

    def delete_blob(self, record: StoredFile) -> bool:
        """Remove the encrypted bytes for ``record`` from storage."""
        return self.storage.delete(record.stored_filename)

    def exists(self, record: StoredFile) -> bool:
        return self.storage.exists(record.stored_filename)
