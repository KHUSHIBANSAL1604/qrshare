"""Small presentation helpers shared by templates and JSON responses."""
from __future__ import annotations

import unicodedata
from datetime import datetime, timezone
from urllib.parse import quote

_UNITS = ("B", "KB", "MB", "GB", "TB")


def human_size(num_bytes: int | None) -> str:
    """Render a byte count the way a file manager would."""
    size = float(num_bytes or 0)
    for unit in _UNITS:
        if size < 1024 or unit == _UNITS[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"  # pragma: no cover - unreachable


def human_duration(seconds: int) -> str:
    """Compact, human-readable countdown, e.g. "1h 05m" or "42s"."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours:02d}h"


def iso(value: datetime | None) -> str | None:
    """UTC ISO-8601 with an explicit offset, for the browser to localise."""
    if value is None:
        return None
    aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).isoformat()


def content_disposition(filename: str, disposition: str = "attachment") -> str:
    """Build a Content-Disposition value that is valid for any filename.

    HTTP header values are latin-1, so a name like ``rapport-ete-2026.pdf``
    with accents cannot go in the plain ``filename`` parameter. RFC 6266/5987
    covers this: an ASCII-folded fallback for old clients plus a percent-
    encoded UTF-8 ``filename*`` that every current browser prefers.
    """
    folded = unicodedata.normalize("NFKD", filename).encode("ascii", "ignore").decode()
    # The name is already sanitised upstream; strip quoting characters anyway
    # so a crafted value can never break out of the quoted string.
    folded = folded.replace('"', "").replace("\\", "").strip() or "download"
    return f"{disposition}; filename=\"{folded}\"; filename*=UTF-8''{quote(filename, safe='')}"
