"""HTTP hardening applied to every response."""
from __future__ import annotations

import secrets

from flask import Flask, g, request

#: No inline scripts are used anywhere; a per-request nonce covers the two
#: small bootstrap blocks that pass server data to the page.
BASE_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-{nonce}'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "object-src 'none'"
)


def init_security(app: Flask) -> None:
    """Install the security headers and the CSP nonce generator."""

    @app.before_request
    def _assign_nonce() -> None:
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def _expose_nonce() -> dict[str, str]:
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    @app.after_request
    def _apply_headers(response):
        nonce = getattr(g, "csp_nonce", "")
        response.headers.setdefault("Content-Security-Policy", BASE_CSP.format(nonce=nonce))
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"
        )
        # Share pages are bearer-token URLs: never let a proxy or the browser
        # keep a copy that a later visitor could pull out of cache.
        if request.path.startswith(("/s/", "/share/", "/api/")):
            response.headers.setdefault("Cache-Control", "no-store, max-age=0")
            response.headers.setdefault("Pragma", "no-cache")
        # HSTS is a promise the deployment has to keep. Enabling it over plain
        # HTTP would lock users out, so it is opt-in and only sent on TLS.
        if app.config.get("ENABLE_HSTS") and request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response
