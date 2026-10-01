"""HTTP layer. Route handlers stay thin and delegate to services."""
from __future__ import annotations

from flask import current_app, request, session, url_for

#: session key holding owner tokens for shares created by this browser
OWNER_SESSION_KEY = "owned_shares"
#: cap the session cookie size; oldest entries fall off
MAX_REMEMBERED_SHARES = 20


def absolute_url(endpoint: str, **values) -> str:
    """Build an absolute URL for a link a user will copy or scan.

    Prefers ``PUBLIC_BASE_URL`` so a deployment behind a proxy advertises its
    real https:// address rather than whatever Host header happened to arrive.
    """
    base = current_app.config.get("PUBLIC_BASE_URL")
    path = url_for(endpoint, **values)
    if base:
        return f"{base}{path}"
    return request.url_root.rstrip("/") + path


def share_url(token: str) -> str:
    """Absolute URL embedded in the QR code."""
    return absolute_url("share.view", token=token)


def manage_url(token: str, owner_token: str) -> str:
    """Absolute private link that lets the sender return to the manage page."""
    return absolute_url("share.manage", token=token, key=owner_token)


def remember_owner(token: str, owner_token: str) -> None:
    """Record in the signed session that this browser created the share."""
    owned: dict[str, str] = dict(session.get(OWNER_SESSION_KEY) or {})
    owned[token] = owner_token
    if len(owned) > MAX_REMEMBERED_SHARES:
        for stale in list(owned)[: len(owned) - MAX_REMEMBERED_SHARES]:
            owned.pop(stale, None)
    session[OWNER_SESSION_KEY] = owned
    session.permanent = False


def remembered_owner_token(token: str) -> str | None:
    owned = session.get(OWNER_SESSION_KEY) or {}
    value = owned.get(token)
    return value if isinstance(value, str) else None


def forget_owner(token: str) -> None:
    owned: dict[str, str] = dict(session.get(OWNER_SESSION_KEY) or {})
    if owned.pop(token, None) is not None:
        session[OWNER_SESSION_KEY] = owned
