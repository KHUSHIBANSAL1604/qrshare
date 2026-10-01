"""Encryption service: round-trips, key isolation, and tamper detection."""
from __future__ import annotations

import io
import os

import pytest

from app.services.encryption_service import (
    HEADER_LEN,
    DecryptionError,
    EncryptionService,
)


@pytest.fixture
def service():
    # A small chunk size so multi-frame behaviour is exercised by tiny inputs.
    return EncryptionService(b"\x02" * 32, chunk_size=64)


def encrypt(service: EncryptionService, data: bytes, key: bytes) -> bytes:
    return b"".join(service.encrypt_stream(io.BytesIO(data), key))


@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 200, 4096])
def test_round_trip_across_frame_boundaries(service, size):
    plaintext = os.urandom(size)
    key = service.generate_file_key()
    blob = encrypt(service, plaintext, key)
    assert service.decrypt_to_bytes(io.BytesIO(blob), key) == plaintext


def test_encrypted_size_matches_the_formula(service):
    plaintext = os.urandom(150)
    key = service.generate_file_key()
    assert len(encrypt(service, plaintext, key)) == service.encrypted_size(150)


def test_ciphertext_does_not_contain_the_plaintext(service):
    plaintext = b"CONFIDENTIAL-MARKER-9f2a" * 20
    key = service.generate_file_key()
    blob = encrypt(service, plaintext, key)
    assert b"CONFIDENTIAL-MARKER" not in blob
    assert blob[:4] == b"QRS1"


def test_each_file_gets_a_distinct_key(service):
    keys = {service.generate_file_key() for _ in range(50)}
    assert len(keys) == 50
    assert all(len(k) == 32 for k in keys)


def test_same_plaintext_twice_gives_different_ciphertext(service):
    plaintext = b"identical input"
    blob_a = encrypt(service, plaintext, service.generate_file_key())
    blob_b = encrypt(service, plaintext, service.generate_file_key())
    assert blob_a != blob_b


def test_wrong_key_fails_instead_of_returning_garbage(service):
    blob = encrypt(service, b"secret", service.generate_file_key())
    with pytest.raises(DecryptionError):
        service.decrypt_to_bytes(io.BytesIO(blob), service.generate_file_key())


def test_flipped_ciphertext_bit_is_detected(service):
    key = service.generate_file_key()
    blob = bytearray(encrypt(service, os.urandom(100), key))
    blob[HEADER_LEN + 8] ^= 0x01
    with pytest.raises(DecryptionError):
        service.decrypt_to_bytes(io.BytesIO(bytes(blob)), key)


def test_truncated_blob_is_detected(service):
    """Dropping the final frame must fail, not silently return a short file."""
    key = service.generate_file_key()
    blob = encrypt(service, os.urandom(300), key)  # 5 frames at chunk_size=64
    truncated = blob[: HEADER_LEN + (4 + 64 + 16)]  # header + one frame only
    with pytest.raises(DecryptionError):
        service.decrypt_to_bytes(io.BytesIO(truncated), key)


def test_reordered_frames_are_detected(service):
    """Frame index is authenticated, so swapping two frames must fail."""
    key = service.generate_file_key()
    blob = encrypt(service, os.urandom(192), key)  # 3 frames
    frame = 4 + 64 + 16
    body = blob[HEADER_LEN:]
    swapped = blob[:HEADER_LEN] + body[frame : frame * 2] + body[:frame] + body[frame * 2 :]
    with pytest.raises(DecryptionError):
        service.decrypt_to_bytes(io.BytesIO(swapped), key)


def test_header_magic_is_checked(service):
    key = service.generate_file_key()
    blob = encrypt(service, b"data", key)
    with pytest.raises(DecryptionError):
        service.decrypt_to_bytes(io.BytesIO(b"XXXX" + blob[4:]), key)


def test_empty_input_is_not_forgeable_as_a_bare_header(service):
    key = service.generate_file_key()
    blob = encrypt(service, b"", key)
    assert service.decrypt_to_bytes(io.BytesIO(blob), key) == b""
    with pytest.raises(DecryptionError):
        service.decrypt_to_bytes(io.BytesIO(blob[:HEADER_LEN]), key)


# -- key wrapping ----------------------------------------------------------
def test_key_wrapping_round_trip(service):
    key = service.generate_file_key()
    assert service.unwrap_key(service.wrap_key(key)) == key


def test_wrapped_key_is_not_the_raw_key(service):
    key = service.generate_file_key()
    assert key not in service.wrap_key(key)


def test_wrapped_key_from_another_master_is_rejected(service):
    other = EncryptionService(b"\x03" * 32, chunk_size=64)
    wrapped = other.wrap_key(other.generate_file_key())
    with pytest.raises(DecryptionError):
        service.unwrap_key(wrapped)


def test_tampered_wrapped_key_is_rejected(service):
    wrapped = bytearray(service.wrap_key(service.generate_file_key()))
    wrapped[-1] ^= 0xFF
    with pytest.raises(DecryptionError):
        service.unwrap_key(bytes(wrapped))


def test_master_key_must_be_32_bytes():
    with pytest.raises(ValueError):
        EncryptionService(b"short")


def test_streaming_does_not_buffer_the_whole_file(service):
    """The generator must emit its first frame before reading everything."""
    source = io.BytesIO(os.urandom(64 * 20))
    stream = service.encrypt_stream(source, service.generate_file_key())
    next(stream)  # header
    next(stream)  # first frame
    assert source.tell() < 64 * 20
