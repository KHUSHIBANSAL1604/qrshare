"""Filesystem storage for encrypted blobs.

The root directory must live outside ``app/static`` so nothing here is ever
reachable over HTTP. Keys are validated against a strict pattern before they
touch the filesystem, which is what makes path traversal impossible even if a
key were ever influenced by user input.
"""
from __future__ import annotations

import logging
import os
import re
import tempfile
from pathlib import Path
from typing import BinaryIO, Iterator

from app.services.storage.base import StorageBackend, StorageError

logger = logging.getLogger(__name__)

#: 48 hex characters produced by ``StorageBackend.new_key`` plus ".enc"
KEY_PATTERN = re.compile(r"^[0-9a-f]{16,64}\.enc$")


class LocalStorageBackend(StorageBackend):
    """Stores each object as one file directly under ``root``."""

    name = "local"

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    # -- path safety -------------------------------------------------------
    def _path(self, key: str) -> Path:
        """Resolve ``key`` to a path, refusing anything suspicious.

        Two independent defences: the key must match a strict allowlist
        pattern, and the resolved path must still sit inside ``root``.
        """
        if not isinstance(key, str) or not KEY_PATTERN.match(key):
            raise StorageError("invalid storage key")
        candidate = (self.root / key).resolve()
        if candidate.parent != self.root:
            raise StorageError("storage key escapes the storage root")
        return candidate

    # -- interface ---------------------------------------------------------
    def save(self, key: str, chunks: Iterator[bytes]) -> int:
        target = self._path(key)
        written = 0
        # Write to a temp file in the same directory and rename, so a crash
        # mid-upload never leaves a half-written blob under a live key.
        fd, tmp_name = tempfile.mkstemp(dir=self.root, suffix=".part")
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                for chunk in chunks:
                    handle.write(chunk)
                    written += len(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, target)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
        return written

    def open(self, key: str) -> BinaryIO:
        path = self._path(key)
        if not path.is_file():
            raise StorageError("stored object is missing")
        return path.open("rb")

    def delete(self, key: str) -> bool:
        try:
            path = self._path(key)
        except StorageError:
            logger.warning("refused to delete an invalid storage key")
            return False
        try:
            path.unlink()
            return True
        except FileNotFoundError:
            return False
        except OSError:
            logger.exception("failed to delete a stored object")
            return False

    def exists(self, key: str) -> bool:
        try:
            return self._path(key).is_file()
        except StorageError:
            return False

    def list_keys(self) -> Iterator[str]:
        for entry in self.root.iterdir():
            if entry.is_file() and KEY_PATTERN.match(entry.name):
                yield entry.name
