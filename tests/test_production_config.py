"""Production configuration: database URLs, proxy handling, public URLs.

These cover the settings that only differ in a hosted deployment, which is
exactly where a mistake is least visible locally and most damaging live.
"""
from __future__ import annotations

import io

import pytest

from app.config import _database_url


# -- database URL normalisation --------------------------------------------
@pytest.mark.parametrize(
    "given,expected_prefix",
    [
        ("postgres://u:p@host/db", "postgresql+psycopg://"),
        ("postgresql://u:p@host/db", "postgresql+psycopg://"),
        ("postgresql+psycopg://u:p@host/db", "postgresql+psycopg://"),
        ("sqlite:///local.db", "sqlite:///"),
    ],
)
def test_database_url_is_normalised(monkeypatch, given, expected_prefix):
    """Managed providers hand out `postgres://`, which SQLAlchemy 2 rejects."""
    monkeypatch.setenv("DATABASE_URL", given)
    assert _database_url().startswith(expected_prefix)


def test_database_url_keeps_credentials_and_host(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://user:pw@db.example.com:5432/qrshare")
    url = _database_url()
    assert url.endswith("@db.example.com:5432/qrshare")
    assert "user:pw" in url


def test_database_url_falls_back_to_sqlite(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert _database_url().startswith("sqlite:///")


def test_blank_database_url_falls_back_to_sqlite(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "   ")
    assert _database_url().startswith("sqlite:///")


# -- public URLs in QR codes -----------------------------------------------
def test_qr_uses_public_base_url_when_set(app, client):
    """The single most important production setting: a QR that encodes
    localhost is useless to the phone scanning it."""
    app.config["PUBLIC_BASE_URL"] = "https://qrshare.onrender.com"
    try:
        created = client.post(
            "/api/upload",
            data={"file": (io.BytesIO(b"x"), "a.txt")},
            content_type="multipart/form-data",
        ).get_json()
        assert created["share_url"].startswith("https://qrshare.onrender.com/s/")
        assert "127.0.0.1" not in created["share_url"]
        assert "localhost" not in created["share_url"]
    finally:
        app.config["PUBLIC_BASE_URL"] = ""


def test_forwarded_proto_produces_https_share_urls(app):
    """Behind a TLS-terminating proxy the app must advertise https://.

    Without ProxyFix the app sees plain http and would mint http:// QR codes,
    which browsers then flag as mixed content.
    """
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    client = app.test_client()
    created = client.post(
        "/api/upload",
        data={"file": (io.BytesIO(b"x"), "a.txt")},
        content_type="multipart/form-data",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "qrshare.onrender.com",
        },
    ).get_json()
    assert created["share_url"].startswith("https://qrshare.onrender.com/s/")


def test_proxy_forwarded_ip_is_used_for_rate_limiting(app):
    """One shared bucket for every visitor would make rate limits useless."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    seen = {}

    @app.route("/__probe")
    def probe():
        from flask import request

        seen["ip"] = request.remote_addr
        return {"ok": True}

    app.test_client().get("/__probe", headers={"X-Forwarded-For": "203.0.113.9"})
    assert seen["ip"] == "203.0.113.9"


# -- production safety rails ------------------------------------------------
def test_production_refuses_to_start_without_secrets(monkeypatch):
    from app import create_app

    monkeypatch.setenv("FLASK_ENV", "production")
    with pytest.raises(RuntimeError, match="Missing required secrets"):
        create_app("production", SECRET_KEY="", MASTER_ENCRYPTION_KEY="")


def test_production_rejects_a_malformed_master_key():
    from app import create_app

    with pytest.raises(RuntimeError, match="Invalid MASTER_ENCRYPTION_KEY"):
        create_app("production", SECRET_KEY="x" * 32, MASTER_ENCRYPTION_KEY="too-short")


def test_debug_is_off_in_production():
    from app.config import get_config

    assert get_config("production").DEBUG is False
    assert get_config("production").ENV_NAME == "production"


def test_hsts_only_sent_over_tls(app):
    """Advertising HSTS over plain HTTP would lock users out of the site."""
    app.config["ENABLE_HSTS"] = True
    try:
        plain = app.test_client().get("/")
        assert "Strict-Transport-Security" not in plain.headers

        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)
        secure = app.test_client().get("/", headers={"X-Forwarded-Proto": "https"})
        assert "Strict-Transport-Security" in secure.headers
    finally:
        app.config["ENABLE_HSTS"] = False


# -- blueprint sanity -------------------------------------------------------
def test_render_blueprint_matches_the_app():
    """Catch a render.yaml that drifts away from how the app actually runs."""
    import pathlib
    import re

    text = pathlib.Path("render.yaml").read_text(encoding="utf-8")
    assert "gunicorn run:app" in text, "start command must target the real WSGI app"
    assert "--bind 0.0.0.0:$PORT" in text, "must bind the port Render provides"
    assert "healthCheckPath: /healthz" in text
    assert "STORAGE_BACKEND" in text and "database" in text, (
        "production must not store blobs on the ephemeral container disk"
    )
    assert "value: local" not in text
    assert "TRUST_PROXY" in text
    # Secrets must never carry a literal value in a committed file.
    for secret in ("MASTER_ENCRYPTION_KEY",):
        block = re.search(rf"- key: {secret}\n(.*?)(?=\n      - key:|\Z)", text, re.S)
        assert block and "sync: false" in block.group(1), f"{secret} must be sync: false"


def test_vercel_page_has_no_leftover_placeholder_after_configuration():
    """Before deploy the placeholder is expected; this test documents that the
    page must point at a real https backend once it has been filled in."""
    import pathlib

    html = pathlib.Path("vercel/index.html").read_text(encoding="utf-8")
    if "__BACKEND_URL__" in html:
        pytest.skip("backend URL not configured yet (pre-deployment)")
    assert "https://" in html
    assert "localhost" not in html and "127.0.0.1" not in html
