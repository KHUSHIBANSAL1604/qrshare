"""Security regression tests: traversal, injection, XSS, headers, rate limits."""
from __future__ import annotations

import io

import pytest
from conftest import share_row, upload_payload

from app.extensions import db
from app.models import StoredFile
from app.services.storage import LocalStorageBackend, StorageError
from app.utils.validation import sanitize_filename

JSON = {"Accept": "application/json"}


# -- path traversal --------------------------------------------------------
@pytest.mark.parametrize(
    "hostile",
    [
        "../../../../etc/passwd",
        "..\\..\\..\\Windows\\System32\\config\\SAM",
        "/etc/shadow",
        "C:\\Windows\\win.ini",
        "....//....//secret.txt",
        "normal/../../escape.txt",
        "%2e%2e%2fetc%2fpasswd",
    ],
)
def test_traversal_filenames_cannot_escape_storage(client, storage_dir, hostile):
    response = client.post(
        "/api/upload",
        data=upload_payload(b"payload", hostile),
        content_type="multipart/form-data",
    )
    assert response.status_code == 201

    blobs = list(storage_dir.iterdir())
    assert len(blobs) >= 1
    for blob in blobs:
        # Everything landed directly in the storage root under a random name.
        assert blob.parent == storage_dir
        assert blob.name.endswith(".enc")
        assert ".." not in blob.name
        assert "/" not in blob.name and "\\" not in blob.name


def test_sanitize_filename_strips_directory_components():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\windows\\win.ini") == "win.ini"
    assert sanitize_filename("/absolute/path/file.txt") == "file.txt"
    assert sanitize_filename("") == "download"
    assert sanitize_filename(None) == "download"
    assert "\x00" not in sanitize_filename("null\x00byte.txt")


def test_storage_backend_rejects_crafted_keys(tmp_path):
    backend = LocalStorageBackend(tmp_path / "blobs")
    for key in ["../escape.enc", "sub/dir.enc", "..\\escape.enc", "no-extension", "/abs.enc"]:
        with pytest.raises(StorageError):
            backend.open(key)
        assert backend.exists(key) is False
        assert backend.delete(key) is False


def test_storage_backend_accepts_its_own_keys(tmp_path):
    backend = LocalStorageBackend(tmp_path / "blobs")
    key = backend.new_key()
    backend.save(key, iter([b"abc"]))
    assert backend.exists(key)
    with backend.open(key) as handle:
        assert handle.read() == b"abc"
    assert backend.delete(key) is True


# -- XSS -------------------------------------------------------------------
@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>.pdf",
        "'+alert(document.cookie)+'.doc",
        "<svg/onload=alert(1)>.png",
        "<iframe src=javascript:alert(1)>.png",
        "</title><script>alert(1)</script>.gif",
    ],
)
def test_xss_in_filenames_is_never_reflected_as_markup(client, fresh_client, payload):
    body = client.post(
        "/api/upload", data=upload_payload(b"x", payload), content_type="multipart/form-data"
    ).get_json()

    # The property that matters is that the payload never becomes markup.
    # Angle brackets and quotes are stripped during sanitisation and Jinja
    # autoescapes whatever survives, so no tag can be reconstructed. (The
    # manage page legitimately contains an <img> for the QR code, so the
    # assertions target the attacker's exact markup, not tags in general.)
    attacker_markup = [
        "<script>alert",
        "<img src=x",
        "<svg/onload",
        "onerror=alert(1)>",
        "javascript:",
    ]
    for page in (
        fresh_client.get(f"/s/{body['token']}").get_data(as_text=True),
        client.get(f"/share/{body['token']}").get_data(as_text=True),
    ):
        assert payload not in page, "payload was reflected verbatim"
        for marker in attacker_markup:
            assert marker not in page


def test_a_quote_in_a_filename_is_rejected_not_stored(client, app):
    """A double quote terminates the quoted string in the multipart header,
    so Werkzeug drops the filename before the app ever sees it. The upload is
    then refused cleanly rather than being stored under a blank name."""
    response = client.post(
        "/api/upload",
        data=upload_payload(b"x", '"><img src=x onerror=alert(1)>.txt'),
        content_type="multipart/form-data",
        headers=JSON,
    )
    assert response.status_code == 400
    assert "<img" not in response.get_data(as_text=True)
    with app.app_context():
        assert db.session.query(StoredFile).count() == 0


def test_dangerous_characters_are_stripped_from_stored_names(client, app):
    client.post(
        "/api/upload",
        data=upload_payload(b"x", '<script>"bad".txt'),
        content_type="multipart/form-data",
    )
    with app.app_context():
        name = db.session.query(StoredFile).one().original_filename
        assert "<" not in name and ">" not in name and '"' not in name


def test_json_status_escapes_hostile_filenames(fresh_client, client):
    body = client.post(
        "/api/upload",
        data=upload_payload(b"x", "</script><script>alert(1)</script>.txt"),
        content_type="multipart/form-data",
    ).get_json()
    raw = fresh_client.get(f"/api/share/{body['token']}/status").get_data(as_text=True)
    assert "<script>" not in raw


# -- SQL injection ---------------------------------------------------------
@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1",
        "'; DROP TABLE shares;--",
        "1 UNION SELECT token FROM shares",
        "%27%20OR%201=1--",
    ],
)
def test_sql_injection_in_tokens_is_inert(fresh_client, make_share, payload, app):
    make_share()  # a real share must still exist afterwards
    assert fresh_client.get(f"/s/{payload}").status_code == 404
    assert fresh_client.get(f"/api/share/{payload}/status").status_code == 404
    with app.app_context():
        assert db.session.query(StoredFile).count() == 1


def test_injection_in_a_filename_does_not_execute(client, app):
    client.post(
        "/api/upload",
        data=upload_payload(b"x", "'; DROP TABLE files;--.txt"),
        content_type="multipart/form-data",
    )
    with app.app_context():
        assert db.session.query(StoredFile).count() == 1


# -- token guessing --------------------------------------------------------
@pytest.mark.parametrize(
    "token", ["1", "abc", "null", "undefined", "0" * 64, "a" * 43, "../../s/real"]
)
def test_guessed_tokens_are_404(fresh_client, make_share, token):
    make_share()
    assert fresh_client.get(f"/s/{token}").status_code == 404


def test_a_wrong_token_is_indistinguishable_from_a_malformed_one(fresh_client):
    malformed = fresh_client.get("/s/!!!not-a-token!!!")
    wrong = fresh_client.get("/s/" + "A" * 43)
    assert malformed.status_code == wrong.status_code == 404


# -- security headers ------------------------------------------------------
def test_security_headers_are_present(client):
    headers = client.get("/").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "same-origin"
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_share_pages_are_not_cacheable(fresh_client, make_share):
    body = make_share()
    assert "no-store" in fresh_client.get(f"/s/{body['token']}").headers["Cache-Control"]
    assert "no-store" in fresh_client.get(
        f"/api/share/{body['token']}/status"
    ).headers["Cache-Control"]


def test_hsts_is_absent_over_plain_http(client):
    """Claiming HTTPS the deployment does not have would lock users out."""
    assert "Strict-Transport-Security" not in client.get("/").headers


def test_each_response_gets_a_fresh_csp_nonce(client):
    first = client.get("/").headers["Content-Security-Policy"]
    second = client.get("/").headers["Content-Security-Policy"]
    assert first != second


# -- error leakage ---------------------------------------------------------
def test_404_page_does_not_leak_internals(fresh_client):
    page = fresh_client.get("/no-such-page").get_data(as_text=True)
    assert "Traceback" not in page
    assert "sqlalchemy" not in page.lower()
    assert "C:\\" not in page and "/home/" not in page


def test_api_errors_return_structured_json(fresh_client):
    response = fresh_client.get("/api/share/nope-nope-nope-nope/status", headers=JSON)
    assert response.status_code == 404
    body = response.get_json()
    assert body["ok"] is False
    assert "Traceback" not in str(body)


def test_browser_navigation_to_a_dead_api_link_gets_html(fresh_client, make_share, app):
    """Clicking a download link for a used share must show a page, not JSON."""
    body = make_share(one_time="true")
    fresh_client.get(f"/api/share/{body['token']}/download")
    response = fresh_client.get(
        f"/api/share/{body['token']}/download", headers={"Accept": "text/html"}
    )
    assert response.status_code == 410
    assert response.mimetype == "text/html"
    assert "No longer available" in response.get_data(as_text=True)


# -- CSRF ------------------------------------------------------------------
def test_state_changing_endpoints_require_csrf_when_enabled(app, tmp_path):
    """CSRF is disabled in the test config; switch it on to prove it works."""
    app.config["WTF_CSRF_ENABLED"] = True
    client = app.test_client()
    response = client.post(
        "/api/upload",
        data=upload_payload(b"x", "a.txt"),
        content_type="multipart/form-data",
        headers=JSON,
    )
    assert response.status_code == 400
    app.config["WTF_CSRF_ENABLED"] = False


# -- rate limiting ---------------------------------------------------------
def test_rate_limiting_blocks_password_brute_force(limited_app):
    """Guessing must stop long before 256 bits of token matter."""
    client = limited_app.test_client()
    body = client.post(
        "/api/upload",
        data=upload_payload(
            b"x", "a.txt", password_protect="true", password="abcdef1", password_confirm="abcdef1"
        ),
        content_type="multipart/form-data",
    ).get_json()

    statuses = [
        client.post(
            f"/api/share/{body['token']}/verify-password", json={"password": f"guess{i}"}
        ).status_code
        for i in range(10)
    ]
    assert 429 in statuses, f"expected a 429 within 10 attempts, got {statuses}"
    assert statuses.index(429) == 5  # the configured "5 per minute" budget
    assert statuses[-1] == 429  # and it stays blocked


def test_rate_limiting_blocks_upload_flooding(limited_app):
    client = limited_app.test_client()
    statuses = [
        client.post(
            "/api/upload",
            data={"file": (io.BytesIO(b"x" * 10), f"f{i}.txt")},
            content_type="multipart/form-data",
        ).status_code
        for i in range(6)
    ]
    assert statuses[:3] == [201, 201, 201]
    assert statuses[3:] == [429, 429, 429]


def test_rate_limited_response_is_a_friendly_page(limited_app):
    client = limited_app.test_client()
    for _ in range(4):
        client.post(
            "/api/upload",
            data=upload_payload(b"x", "a.txt"),
            content_type="multipart/form-data",
        )
    response = client.post(
        "/api/upload",
        data=upload_payload(b"x", "a.txt"),
        content_type="multipart/form-data",
        headers={"Accept": "text/html"},
    )
    assert response.status_code == 429
    page = response.get_data(as_text=True)
    assert "Too many requests" in page
    assert "Traceback" not in page


# -- upload safety ---------------------------------------------------------
def test_uploads_are_never_written_into_the_static_directory(client, app, storage_dir):
    client.post("/api/upload", data=upload_payload(b"x", "a.txt"), content_type="multipart/form-data")
    static_root = app.static_folder
    assert str(storage_dir).lower() not in str(static_root).lower()
    assert not any(p.suffix == ".enc" for p in __import__("pathlib").Path(static_root).rglob("*"))


def test_html_upload_is_served_as_an_attachment_not_rendered(fresh_client, client):
    body = client.post(
        "/api/upload",
        data=upload_payload(b"<script>alert('stored xss')</script>", "evil.html"),
        content_type="multipart/form-data",
    ).get_json()
    response = fresh_client.get(f"/api/share/{body['token']}/download")
    assert response.headers["Content-Type"] == "application/octet-stream"
    assert response.headers["Content-Disposition"].startswith("attachment")
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_declared_mime_type_is_not_trusted(client, app):
    """A browser-supplied Content-Type must never dictate how we serve it."""
    data = {"file": (io.BytesIO(b"x"), "a.txt", "text/html; charset=utf-8")}
    body = client.post("/api/upload", data=data, content_type="multipart/form-data").get_json()
    response = client.get(f"/api/share/{body['token']}/download")
    assert response.headers["Content-Type"] == "application/octet-stream"


def test_owner_token_is_not_exposed_in_public_views(fresh_client, make_share, app):
    body = make_share()
    with app.app_context():
        owner = share_row(body["token"]).owner_token
    assert owner not in fresh_client.get(f"/s/{body['token']}").get_data(as_text=True)
    assert owner not in fresh_client.get(
        f"/api/share/{body['token']}/status"
    ).get_data(as_text=True)


# -- rate-limit scoping ----------------------------------------------------
def test_static_assets_do_not_consume_the_rate_budget(limited_app):
    """A normal page load pulls a stylesheet, four scripts and a favicon.
    Counting those against the default budget would throttle real visitors."""
    client = limited_app.test_client()
    for _ in range(40):
        assert client.get("/static/css/main.css").status_code == 200
        assert client.get("/static/js/common.js").status_code == 200
    assert client.get("/").status_code == 200


def test_health_probe_is_never_throttled(limited_app):
    client = limited_app.test_client()
    for _ in range(50):
        assert client.get("/healthz").status_code == 200


# -- public URLs -----------------------------------------------------------
def test_public_base_url_is_used_for_both_share_and_manage_links(app, make_share):
    """Behind a proxy the QR must advertise the real https:// address, and the
    manage link has to agree with it."""
    app.config["PUBLIC_BASE_URL"] = "https://share.example.edu"
    try:
        client = app.test_client()
        created = client.post(
            "/api/upload",
            data=upload_payload(b"x", "a.txt"),
            content_type="multipart/form-data",
        ).get_json()
        assert created["share_url"].startswith("https://share.example.edu/s/")
        assert created["manage_url_absolute"].startswith("https://share.example.edu/share/")

        page = client.get(f"/share/{created['token']}").get_data(as_text=True)
        assert "https://share.example.edu/s/" in page
        assert "https://share.example.edu/share/" in page
    finally:
        app.config["PUBLIC_BASE_URL"] = ""


def test_cancel_keeps_a_blob_that_another_live_share_still_needs(app, client, make_share):
    """Two shares over one file: cancelling one must not shred the other's bytes."""
    from app.extensions import db as _db
    from app.services import services as _services

    body = make_share(content=b"shared between two links")
    with app.app_context():
        original = share_row(body["token"])
        registry = app.extensions["qrshare"]
        second = registry.shares.create_share(original.file, expiry_minutes=60)
        _db.session.commit()
        second_token = second.token

    client.post(f"/api/share/{body['token']}/cancel", json={"key": body["owner_key"]})

    # The first link is dead; the second still serves the file.
    assert client.get(
        f"/api/share/{body['token']}/download", headers=JSON
    ).status_code == 410
    survivor = client.get(f"/api/share/{second_token}/download")
    assert survivor.status_code == 200
    assert survivor.data == b"shared between two links"
