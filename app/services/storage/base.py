"""Storage backend interface.

Share and file management code talks only to this interface, so adding an
S3 (or any other) backend later means implementing four methods rather than
touching business logic.
"""
from __future__ import annotations

import abc
from typing import BinaryIO, Iterator


class StorageError(Exception):
    """Raised when the backend cannot satisfy a request."""


class StorageBackend(abc.ABC):
    """Persists opaque byte streams under an opaque key."""

    #: short identifier persisted on the file row, e.g. "local" or "s3"
    name: str = "abstract"

    @abc.abstractmethod
    def save(self, key: str, chunks: Iterator[bytes]) -> int:
        """Persist ``chunks`` under ``key``. Returns bytes written."""

    @abc.abstractmethod
    def open(self, key: str) -> BinaryIO:
        """Open the stored object for reading. Caller must close it."""

    @abc.abstractmethod
    def delete(self, key: str) -> bool:
        """Remove the object. Returns ``True`` if something was removed."""

    @abc.abstractmethod
    def exists(self, key: str) -> bool:
        """Whether the object is present."""

    @abc.abstractmethod
    def list_keys(self) -> Iterator[str]:
        """Every key the backend currently holds (used to find orphans)."""

    @staticmethod
    def new_key(suffix: str = ".enc") -> str:
        """A random, opaque object key. Never derived from user input."""
        import secrets

        return secrets.token_hex(24) + suffix
