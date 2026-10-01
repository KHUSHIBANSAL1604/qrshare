"""Share password hashing.

Argon2id is preferred. If ``argon2-cffi`` is not installed the module falls
back to Werkzeug's scrypt, which ships with Flask -- both are memory-hard and
salted, so the fallback is a downgrade in tuning, not in kind. Plaintext
passwords are never stored or logged.
"""
from __future__ import annotations

import logging
import secrets

logger = logging.getLogger(__name__)

try:  # pragma: no cover - depends on the installed environment
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

    _hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)
    ALGORITHM = "argon2id"

    def hash_password(password: str) -> str:
        return _hasher.hash(password)

    def _verify(stored_hash: str, password: str) -> bool:
        try:
            return _hasher.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

except ImportError:  # pragma: no cover - exercised only without argon2-cffi
    from werkzeug.security import check_password_hash, generate_password_hash

    ALGORITHM = "scrypt"
    logger.warning("argon2-cffi is not installed; falling back to werkzeug scrypt")

    def hash_password(password: str) -> str:
        return generate_password_hash(password, method="scrypt")

    def _verify(stored_hash: str, password: str) -> bool:
        try:
            return check_password_hash(stored_hash, password)
        except (ValueError, TypeError):
            return False


#: A syntactically valid hash of a random password, used to keep the timing of
#: "no password set" indistinguishable from "wrong password".
_DUMMY_HASH = hash_password(secrets.token_urlsafe(24))


def verify_password(stored_hash: str | None, password: str | None) -> bool:
    """Constant-ish time password check.

    When ``stored_hash`` is ``None`` the work is still performed against a
    dummy hash so an attacker cannot learn from response timing whether a
    given share is password protected.
    """
    candidate = password or ""
    if not stored_hash:
        _verify(_DUMMY_HASH, candidate)
        return False
    return _verify(stored_hash, candidate)
