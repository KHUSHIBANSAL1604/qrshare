"""Authenticated encryption for stored files.

Design
------
Every file gets its own random 256-bit *data key* (DEK). The DEK is wrapped
with the server master key (AES-256-GCM) and the wrapped blob is what the
database stores, so a database dump alone never reveals a file and a stolen
blob is useless without both the DB row and the master key.

The file body is **not** encrypted as one giant GCM message. A single GCM
message can only be authenticated after the very last byte, which would force
us either to buffer the whole plaintext in RAM or to stream out unverified
plaintext. Instead the plaintext is split into fixed-size frames, each
encrypted with its own nonce and authenticated independently::

    header  : b"QRS1" | nonce_prefix(8) | chunk_size(4, big endian)
    frame*  : ct_len(4, big endian) | ciphertext | tag(16)

    nonce   = nonce_prefix || frame_index(4, big endian)      -> 12 bytes
    AAD     = b"QRS1" | nonce_prefix | frame_index(4) | final_flag(1)

Because the frame index is authenticated, frames cannot be reordered,
duplicated or dropped; because the last frame carries ``final_flag=1``, the
file cannot be truncated without detection. Each frame is verified *before*
its plaintext is yielded, so a consumer never sees unauthenticated bytes.
"""
from __future__ import annotations

import os
import struct
from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"QRS1"
NONCE_PREFIX_LEN = 8
NONCE_LEN = 12
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + NONCE_PREFIX_LEN + 4
KEY_LEN = 32
DEFAULT_CHUNK_SIZE = 1024 * 1024
#: refuse absurd frame headers from a tampered blob instead of allocating them
MAX_CHUNK_SIZE = 64 * 1024 * 1024


class DecryptionError(Exception):
    """Raised when a blob is corrupt, truncated or tampered with."""


class EncryptionService:
    """Wraps data keys and turns plaintext streams into authenticated frames."""

    def __init__(self, master_key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
        if len(master_key) != KEY_LEN:
            raise ValueError("master key must be 32 bytes")
        if not 0 < chunk_size <= MAX_CHUNK_SIZE:
            raise ValueError("chunk_size out of range")
        self._master = AESGCM(master_key)
        self.chunk_size = chunk_size

    # -- data key handling -------------------------------------------------
    @staticmethod
    def generate_file_key() -> bytes:
        """A fresh 256-bit key for exactly one file."""
        return os.urandom(KEY_LEN)

    def wrap_key(self, file_key: bytes) -> bytes:
        """Encrypt a data key under the master key. Returns nonce||ct||tag."""
        if len(file_key) != KEY_LEN:
            raise ValueError("file key must be 32 bytes")
        nonce = os.urandom(NONCE_LEN)
        return nonce + self._master.encrypt(nonce, file_key, MAGIC)

    def unwrap_key(self, wrapped: bytes) -> bytes:
        """Recover a data key. Raises :class:`DecryptionError` if tampered."""
        if len(wrapped) <= NONCE_LEN:
            raise DecryptionError("wrapped key is malformed")
        nonce, body = wrapped[:NONCE_LEN], wrapped[NONCE_LEN:]
        try:
            key = self._master.decrypt(nonce, body, MAGIC)
        except InvalidTag as exc:
            raise DecryptionError("data key failed authentication") from exc
        if len(key) != KEY_LEN:
            raise DecryptionError("unwrapped key has the wrong length")
        return key

    # -- framing helpers ---------------------------------------------------
    @staticmethod
    def _aad(nonce_prefix: bytes, index: int, final: bool) -> bytes:
        return MAGIC + nonce_prefix + struct.pack(">I", index) + (b"\x01" if final else b"\x00")

    @staticmethod
    def _nonce(nonce_prefix: bytes, index: int) -> bytes:
        return nonce_prefix + struct.pack(">I", index)

    # -- encryption --------------------------------------------------------
    def encrypt_stream(self, source: BinaryIO, file_key: bytes) -> Iterator[bytes]:
        """Yield the encrypted representation of ``source``.

        Reads at most ``chunk_size`` bytes at a time, so memory use stays flat
        regardless of file size.
        """
        aesgcm = AESGCM(file_key)
        nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
        yield MAGIC + nonce_prefix + struct.pack(">I", self.chunk_size)

        index = 0
        # An empty file still produces one authenticated final frame, so a
        # zero-byte blob cannot be forged by truncating everything away.
        pending = source.read(self.chunk_size) or b""
        while True:
            lookahead = source.read(self.chunk_size)
            final = not lookahead
            ct = aesgcm.encrypt(
                self._nonce(nonce_prefix, index),
                pending,
                self._aad(nonce_prefix, index, final),
            )
            yield struct.pack(">I", len(ct)) + ct
            if final:
                break
            pending = lookahead
            index += 1

    # -- decryption --------------------------------------------------------
    def decrypt_stream(self, source: BinaryIO, file_key: bytes) -> Iterator[bytes]:
        """Yield verified plaintext frames from an encrypted blob.

        Every frame tag is checked before its plaintext is produced, so a
        consumer never sees unauthenticated data.
        """
        aesgcm = AESGCM(file_key)
        header = _read_exact(source, HEADER_LEN)
        if header[: len(MAGIC)] != MAGIC:
            raise DecryptionError("not a QRShare encrypted blob")
        nonce_prefix = header[len(MAGIC) : len(MAGIC) + NONCE_PREFIX_LEN]
        chunk_size = struct.unpack(">I", header[-4:])[0]
        if not 0 < chunk_size <= MAX_CHUNK_SIZE:
            raise DecryptionError("implausible chunk size in header")

        index = 0
        seen_final = False
        while True:
            length_bytes = source.read(4)
            if not length_bytes:
                break
            if len(length_bytes) != 4:
                raise DecryptionError("truncated frame length")
            if seen_final:
                raise DecryptionError("trailing data after final frame")
            ct_len = struct.unpack(">I", length_bytes)[0]
            if ct_len < TAG_LEN or ct_len > chunk_size + TAG_LEN:
                raise DecryptionError("implausible frame length")
            ct = _read_exact(source, ct_len)
            nonce = self._nonce(nonce_prefix, index)
            # We cannot know in advance whether this is the last frame, so try
            # the final AAD first and fall back to the continuation AAD.
            for final in (True, False):
                try:
                    plaintext = aesgcm.decrypt(nonce, ct, self._aad(nonce_prefix, index, final))
                except InvalidTag:
                    continue
                seen_final = final
                break
            else:
                raise DecryptionError("frame failed authentication")
            yield plaintext
            index += 1

        if not seen_final:
            raise DecryptionError("blob is truncated: no final frame")

    def decrypt_to_bytes(self, source: BinaryIO, file_key: bytes) -> bytes:
        """Convenience wrapper for tests and small files."""
        return b"".join(self.decrypt_stream(source, file_key))

    def encrypted_size(self, plaintext_size: int) -> int:
        """Exact on-disk size for a given plaintext size (used by tests)."""
        frames = max(1, -(-plaintext_size // self.chunk_size))
        return HEADER_LEN + frames * (4 + TAG_LEN) + plaintext_size


def _read_exact(source: BinaryIO, count: int) -> bytes:
    buf = source.read(count)
    if buf is None or len(buf) != count:
        raise DecryptionError("unexpected end of encrypted blob")
    return buf
