"""Server-side input validation.

Everything here runs on the server. The browser performs the same checks for
a better UX, but the client is never trusted: a hand-rolled ``curl`` request
must hit exactly the same rules.
"""
from __future__ import annotations

import mimetypes
import os
import re
import unicodedata
from dataclasses import dataclass

#: characters that are illegal or dangerous in a displayed filename
_UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f<>:\"/\\|?*]")
_WHITESPACE = re.compile(r"\s+")
MAX_FILENAME_LENGTH = 180
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 256


class ValidationError(Exception):
    """A user-facing validation failure.

    ``message`` is safe to show; it never contains paths or internals.
    """

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.field = field


@dataclass(frozen=True)
class FileMeta:
    display_name: str
    extension: str
    mime_type: str


def sanitize_filename(raw: str | None) -> str:
    """Reduce an uploaded filename to something safe to store and display.

    This is *display* metadata only -- the bytes are stored under a random
    key -- but it still gets stripped of directory components, control
    characters and shell/HTML metacharacters so it cannot be abused when it is
    echoed back into a page or a ``Content-Disposition`` header.
    """
    name = (raw or "").strip()
    # Strip any directory component from both separators, including tricks
    # like "..\\..\\evil" arriving from a Windows client.
    name = name.replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFKC", name)
    name = _UNSAFE_CHARS.sub("_", name)
    name = _WHITESPACE.sub(" ", name).strip(" .")
    # Windows reserved device names.
    stem = name.split(".")[0].upper()
    if stem in {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        name = f"file_{name}"
    if len(name) > MAX_FILENAME_LENGTH:
        root, ext = os.path.splitext(name)
        name = root[: MAX_FILENAME_LENGTH - len(ext)] + ext
    return name or "download"


def extension_of(filename: str) -> str:
    return os.path.splitext(filename)[1].lower().lstrip(".")


def validate_upload(
    filename: str | None,
    size: int,
    max_bytes: int,
    allowed: set[str],
    blocked: set[str],
    declared_mime: str | None = None,
) -> FileMeta:
    """Validate an upload and return normalised metadata.

    Raises :class:`ValidationError` with a message suitable for display.
    """
    name = sanitize_filename(filename)
    if not name or name == "download" and not filename:
        raise ValidationError("Please choose a file to share.", "file")

    if size <= 0:
        raise ValidationError("That file is empty, so there is nothing to share.", "file")
    if size > max_bytes:
        limit_mb = max_bytes / (1024 * 1024)
        raise ValidationError(
            f"That file is larger than the {limit_mb:.0f} MB limit.", "file"
        )

    ext = extension_of(name)
    if allowed:
        # Allowlist mode: only listed extensions get through.
        if ext not in allowed:
            raise ValidationError("That file type is not allowed.", "file")
    elif ext and ext in blocked:
        raise ValidationError(
            "Executable file types cannot be shared for security reasons.", "file"
        )

    # The browser-declared content type is a hint only. We keep it for the
    # download response but never let it decide whether the upload is safe,
    # and we normalise anything odd to a neutral binary type.
    guessed, _ = mimetypes.guess_type(name)
    mime = _normalise_mime(declared_mime) or guessed or "application/octet-stream"
    return FileMeta(display_name=name, extension=ext, mime_type=mime)


_MIME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]{0,62}/[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]{0,62}$")


def _normalise_mime(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.split(";")[0].strip().lower()
    if not _MIME_PATTERN.match(candidate):
        return None
    return candidate


def validate_expiry(minutes: int | str | None, default: int, minimum: int, maximum: int) -> int:
    """Clamp and validate a requested share lifetime, in minutes."""
    if minutes is None or minutes == "":
        return default
    try:
        value = int(minutes)
    except (TypeError, ValueError):
        raise ValidationError("Choose a valid expiry time.", "expiry") from None
    if value < minimum or value > maximum:
        raise ValidationError(
            f"Expiry must be between {minimum} minute(s) and {maximum // 60} hour(s).", "expiry"
        )
    return value


def validate_password(password: str | None, confirm: str | None) -> str:
    """Validate a share password. Returns the password to be hashed."""
    if not password:
        raise ValidationError("Enter a password, or turn password protection off.", "password")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", "password"
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        # Bound the work an attacker can force the hasher to do.
        raise ValidationError("That password is too long.", "password")
    if confirm is not None and password != confirm:
        raise ValidationError("The two passwords do not match.", "password")
    return password
