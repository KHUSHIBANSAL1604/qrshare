"""Storage backend that keeps encrypted blobs in the database.

Why this exists
---------------
A container filesystem is not durable: Render and similar hosts hand each
deploy a fresh disk, so blobs written locally vanish on the next restart.
Object storage is the textbook answer, but every mainstream S3 provider wants
card details before it will hand out a bucket. A managed Postgres instance is
already required for the application's own tables, so putting the blobs there
removes an entire third-party dependency and keeps the deployment free.

How it works
------------
Blobs are split into fixed-size rows rather than stored as one enormous value::

    blob_chunks(storage_key, seq, data)   PRIMARY KEY (storage_key, seq)

Writes stream in and are inserted in batches; reads pull one row at a time and
are served through an exact-read adapter. Memory stays flat in both
directions, which is the same property the filesystem and S3 backends have.

Connections are deliberately **not** taken from Flask-SQLAlchemy's scoped
session. A download is streamed by a generator that Flask consumes *after* the
request context has been torn down, so a request-scoped session would already
be closed by the time the second chunk was needed. This backend owns its own
engine and opens a dedicated connection per read, released when the reader is
closed.

Trade-offs, stated plainly: database storage costs more CPU and memory per
byte than an object store, and a free Postgres plan is small (on the order of
1 GB). It suits a demo or light use. Moving to S3 later is a configuration
change, not a rewrite, because both sit behind the same interface.
"""
from __future__ import annotations

import logging
from typing import BinaryIO, Iterator

from sqlalchemy import (
    Column,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    create_engine,
    delete,
    func,
    insert,
    select,
)

from app.services.storage.base import StorageBackend, StorageError
from app.services.storage.local import KEY_PATTERN

logger = logging.getLogger(__name__)

#: Bytes of blob per row. 1 MiB keeps individual rows comfortable for Postgres
#: and matches the encryption frame size, so a frame rarely straddles rows.
DEFAULT_CHUNK = 1024 * 1024
#: Rows per INSERT round trip while uploading.
INSERT_BATCH = 8

_metadata = MetaData()

blob_chunks = Table(
    "blob_chunks",
    _metadata,
    Column("storage_key", String(128), primary_key=True),
    Column("seq", Integer, primary_key=True),
    Column("data", LargeBinary, nullable=False),
)


class _ChunkReader:
    """Serves exact-length reads from a sequence of database rows.

    The decryption framing asks for an exact number of bytes and treats a
    short read as a truncated blob, so this buffers across row boundaries.
    """

    def __init__(self, connection, rows) -> None:
        self._connection = connection
        self._rows = rows
        self._buffer = bytearray()
        self._exhausted = False
        self.closed = False

    def _pull(self) -> bool:
        if self._exhausted:
            return False
        row = self._rows.fetchone()
        if row is None:
            self._exhausted = True
            return False
        self._buffer.extend(row[0])
        return True

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            while self._pull():
                pass
            out = bytes(self._buffer)
            self._buffer.clear()
            return out
        while len(self._buffer) < size and self._pull():
            pass
        count = min(size, len(self._buffer))
        out = bytes(self._buffer[:count])
        del self._buffer[:count]
        return out

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self._rows.close()
        except Exception:  # noqa: BLE001 - closing must never raise upward
            logger.debug("ignored an error closing a blob cursor")
        try:
            self._connection.close()
        except Exception:  # noqa: BLE001
            logger.debug("ignored an error closing a blob connection")

    # Context-manager support so callers may use `with backend.open(k) as f`.
    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


class DatabaseStorageBackend(StorageBackend):
    """Persists encrypted blobs as chunked rows in a SQL database."""

    name = "database"

    def __init__(self, database_url: str, chunk_size: int = DEFAULT_CHUNK) -> None:
        if not database_url:
            raise StorageError("DATABASE_URL is required when STORAGE_BACKEND=database")
        self.chunk_size = chunk_size
        # pool_pre_ping: a free database drops idle connections, and a stale
        # one would surface as a failed download rather than a reconnect.
        self._engine = create_engine(database_url, pool_pre_ping=True, pool_recycle=280)
        _metadata.create_all(self._engine, tables=[blob_chunks], checkfirst=True)

    # -- key safety --------------------------------------------------------
    @staticmethod
    def _check(key: str) -> str:
        if not isinstance(key, str) or not KEY_PATTERN.match(key):
            raise StorageError("invalid storage key")
        return key

    # -- interface ---------------------------------------------------------
    def save(self, key: str, chunks: Iterator[bytes]) -> int:
        """Stream `chunks` into rows. Returns bytes written."""
        self._check(key)
        written = 0
        buffer = bytearray()
        batch: list[dict] = []
        seq = 0

        try:
            with self._engine.begin() as connection:
                def flush_batch() -> None:
                    if batch:
                        connection.execute(insert(blob_chunks), batch)
                        batch.clear()

                for piece in chunks:
                    buffer.extend(piece)
                    written += len(piece)
                    while len(buffer) >= self.chunk_size:
                        batch.append(
                            {
                                "storage_key": key,
                                "seq": seq,
                                "data": bytes(buffer[: self.chunk_size]),
                            }
                        )
                        del buffer[: self.chunk_size]
                        seq += 1
                        if len(batch) >= INSERT_BATCH:
                            flush_batch()

                # Always write a final row, even for an empty blob, so that
                # "stored but zero length" stays distinguishable from "absent".
                if buffer or seq == 0:
                    batch.append({"storage_key": key, "seq": seq, "data": bytes(buffer)})
                flush_batch()
        except StorageError:
            raise
        except Exception as exc:  # noqa: BLE001 - surfaced as a storage failure
            logger.exception("database blob write failed")
            raise StorageError("could not store the object") from exc
        return written

    def open(self, key: str) -> BinaryIO:
        """Open a stored blob for reading.

        Presence is checked up front with a cheap indexed query rather than by
        peeking at the first byte: a legitimately empty blob has a row whose
        data is empty, and a byte-probe cannot tell that apart from a blob
        that was never written.
        """
        self._check(key)
        if not self.exists(key):
            raise StorageError("stored object is missing")
        connection = self._engine.connect()
        try:
            rows = connection.execution_options(stream_results=True, yield_per=1).execute(
                select(blob_chunks.c.data)
                .where(blob_chunks.c.storage_key == key)
                .order_by(blob_chunks.c.seq)
            )
        except Exception as exc:  # noqa: BLE001
            connection.close()
            raise StorageError("stored object is missing") from exc

        return _ChunkReader(connection, rows)  # type: ignore[return-value]

    def delete(self, key: str) -> bool:
        try:
            self._check(key)
        except StorageError:
            logger.warning("refused to delete an invalid storage key")
            return False
        try:
            with self._engine.begin() as connection:
                result = connection.execute(
                    delete(blob_chunks).where(blob_chunks.c.storage_key == key)
                )
            return bool(result.rowcount)
        except Exception:  # noqa: BLE001
            logger.exception("database blob delete failed")
            return False

    def exists(self, key: str) -> bool:
        try:
            self._check(key)
        except StorageError:
            return False
        with self._engine.connect() as connection:
            found = connection.execute(
                select(blob_chunks.c.seq).where(blob_chunks.c.storage_key == key).limit(1)
            ).first()
        return found is not None

    def list_keys(self) -> Iterator[str]:
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(blob_chunks.c.storage_key).distinct()
            ).fetchall()
        for (key,) in rows:
            if KEY_PATTERN.match(key):
                yield key

    # -- operational insight ------------------------------------------------
    def total_bytes(self) -> int:
        """Bytes currently held. Useful against a capped free database."""
        with self._engine.connect() as connection:
            total = connection.execute(
                select(func.coalesce(func.sum(func.length(blob_chunks.c.data)), 0))
            ).scalar()
        return int(total or 0)
