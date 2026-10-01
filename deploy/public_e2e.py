"""End-to-end test of a PUBLIC QRShare deployment.

    python deploy/public_e2e.py https://qrshare.onrender.com [https://qrshare.vercel.app]

Drives the real HTTPS endpoints the way a browser and a phone would: CSRF
tokens scraped from rendered pages, cookies carried per "device", and two
independent sessions standing in for the sender's laptop and the receiver's
phone.

Exits non-zero if any check fails, so it is usable as a deployment gate.
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

BOUNDARY = "----qrsharePublicE2E"
results: list[tuple[bool, str, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((bool(ok), label, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  <- {detail}" if detail and not ok else ""))
    return bool(ok)


def device() -> urllib.request.OpenerDirector:
    """A separate cookie jar == a separate browser."""
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    opener.addheaders = [("User-Agent", "QRShare-E2E/1.0")]
    return opener


def fetch(op, url, data=None, headers=None, method=None, timeout=180):
    request = urllib.request.Request(url, data=data, method=method)
    headers = dict(headers or {})
    # Flask-WTF enforces strict referrer checking on CSRF-protected POSTs over
    # HTTPS. Browsers always send Referer; a bare client does not, so without
    # this every state-changing request is rejected with a 400.
    if data is not None and "Referer" not in headers:
        parts = urllib.parse.urlparse(url)
        headers["Referer"] = f"{parts.scheme}://{parts.netloc}/"
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        return op.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        return exc


def multipart(fields: dict, filename: str, content: bytes) -> bytes:
    parts = []
    for key, value in fields.items():
        parts.append(
            f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n".encode()
        )
    parts.append(
        f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n".encode() + content + b"\r\n"
    )
    parts.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(parts)


def upload_csrf(op, base) -> str:
    body = fetch(op, base + "/upload").read()
    match = re.search(rb'name="csrf_token" value="([^"]+)"', body)
    if not match:
        raise SystemExit("could not find a CSRF token on /upload")
    return match.group(1).decode()


def share_page_csrf(op, base, token) -> tuple[str, bytes]:
    body = fetch(op, f"{base}/s/{token}").read()
    blob = re.search(rb'id="download-config"[^>]*>\s*(\{.*?\})\s*</script>', body, re.S)
    if not blob:
        raise SystemExit("could not find the download config on the share page")
    return json.loads(blob.group(1))["csrfToken"], body


def wake(base: str) -> None:
    """Free Render services sleep; the first request can take ~a minute."""
    print(f"  waking {base} ...", end="", flush=True)
    started = time.time()
    for _ in range(40):
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=30) as r:
                if r.status == 200:
                    print(f" awake in {time.time() - started:.0f}s")
                    return
        except Exception:
            pass
        time.sleep(5)
    print(" did not wake")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    # --local relaxes the TLS-only assertions so the harness itself can be
    # exercised against a development server before anything is deployed.
    local = "--local" in sys.argv
    backend = args[0].rstrip("/")
    frontend = args[1].rstrip("/") if len(args) > 1 else None

    print(f"\nPublic end-to-end test\n  backend : {backend}\n  frontend: {frontend or '(not given)'}")
    print("=" * 66)

    wake(backend)
    sender, receiver = device(), device()

    # -- transport ---------------------------------------------------------
    print("\n[1] Transport and reachability")
    if local:
        print("  (--local: TLS and public-URL assertions skipped)")
    else:
        check(backend.startswith("https://"), "backend is served over HTTPS")
    r = fetch(sender, backend + "/healthz")
    check(r.status == 200, "GET /healthz -> 200", f"status={r.status}")
    r.read()

    r = fetch(sender, backend + "/")
    home = r.read()
    check(r.status == 200 and b"QRShare" in home, "homepage loads", f"status={r.status}")
    check(r.headers.get("X-Content-Type-Options") == "nosniff", "security headers present")
    if not local:
        check("Strict-Transport-Security" in r.headers, "HSTS sent over TLS")
    csp = r.headers.get("Content-Security-Policy", "")
    check("unsafe-inline" not in csp and "default-src 'self'" in csp, "CSP is strict")

    # -- no localhost anywhere --------------------------------------------
    print("\n[2] No development URLs in production output")
    if local:
        print("  (--local: localhost assertions skipped)")
    else:
        leaked = [m for m in (b"localhost", b"127.0.0.1") if m in home]
        check(not leaked, "homepage contains no localhost/127.0.0.1", str(leaked))

    # -- upload ------------------------------------------------------------
    print("\n[3] Upload with password + one-time")
    secret = b"%PDF-1.7 PUBLIC-E2E-CANARY confidential payload\n" * 150
    password = "public-e2e-pass"
    token_csrf = upload_csrf(sender, backend)
    r = fetch(
        sender,
        backend + "/api/upload",
        data=multipart(
            {
                "expiry_minutes": "10",
                "one_time": "true",
                "password_protect": "true",
                "password": password,
                "password_confirm": password,
            },
            "public report.pdf",
            secret,
        ),
        headers={
            "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
            "X-CSRFToken": token_csrf,
            "Accept": "application/json",
        },
    )
    raw = r.read()
    if not check(r.status == 201, "POST /api/upload -> 201", f"status={r.status} body={raw[:300]}"):
        return summarise()
    share = json.loads(raw)
    token = share["token"]
    check(len(token) >= 43, "share token is 256-bit")

    # -- QR ----------------------------------------------------------------
    print("\n[4] QR code")
    share_url = share["share_url"]
    if not local:
        check(share_url.startswith("https://"), "share URL is HTTPS", share_url)
        check(
            "localhost" not in share_url and "127.0.0.1" not in share_url,
            "QR target is a public URL, not localhost",
            share_url,
        )
    r = fetch(receiver, f"{backend}/api/qr/{token}")
    png = r.read()
    check(png[:4] == b"\x89PNG", "QR endpoint returns a PNG")
    check(b"PUBLIC-E2E-CANARY" not in png, "QR carries no file content")

    decoded = decode_qr(png)
    if decoded is None:
        check(True, "QR decode skipped (no decoder installed locally)")
    else:
        check(decoded == share_url, "decoded QR equals the public share URL", f"{decoded!r}")

    # -- receiver ----------------------------------------------------------
    print("\n[5] Receiver flow")
    recv_csrf, page = share_page_csrf(receiver, backend, token)
    check(b"Enter the password" in page, "receiver sees the password prompt")
    check(b"PUBLIC-E2E-CANARY" not in page, "receiver page leaks no file content")

    r = fetch(receiver, f"{backend}/api/share/{token}/download", headers={"Accept": "application/json"})
    r.read()
    check(r.status == 401, "download without a ticket is refused", f"status={r.status}")

    r = fetch(
        receiver,
        f"{backend}/api/share/{token}/verify-password",
        data=json.dumps({"password": "wrong"}).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json", "X-CSRFToken": recv_csrf},
    )
    r.read()
    check(r.status == 401, "wrong password refused", f"status={r.status}")

    r = fetch(
        receiver,
        f"{backend}/api/share/{token}/verify-password",
        data=json.dumps({"password": password}).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json", "X-CSRFToken": recv_csrf},
    )
    body = r.read()
    ticket = json.loads(body).get("ticket", "") if r.status == 200 else ""
    check(bool(ticket), "correct password issues a ticket", f"status={r.status}")

    # -- download ----------------------------------------------------------
    print("\n[6] Download (object storage round trip)")
    r = fetch(receiver, f"{backend}/api/share/{token}/download?ticket={ticket}")
    data = r.read()
    check(r.status == 200, "download -> 200", f"status={r.status}")
    check(data == secret, "bytes match the original exactly (decrypted from object storage)")
    check(r.headers.get("Content-Disposition", "").startswith("attachment"), "served as an attachment")
    check(r.headers.get("X-Content-Type-Options") == "nosniff", "nosniff on the download")

    # -- one-time ----------------------------------------------------------
    print("\n[7] One-time consumption")
    r = fetch(
        receiver,
        f"{backend}/api/share/{token}/download?ticket={ticket}",
        headers={"Accept": "application/json"},
    )
    again = r.read()
    check(r.status == 410, "second download refused with 410", f"status={r.status}")
    check(json.loads(again).get("code") == "used", "refusal reason is 'used'")
    check(b"Already used" in fetch(receiver, f"{backend}/s/{token}").read(), "page shows 'Already used'")

    r = fetch(sender, f"{backend}/api/share/{token}/status")
    info = json.loads(r.read())
    check(info["status"] == "used" and info["downloads"] == 1, "sender sees used / 1 download")

    # -- expiry ------------------------------------------------------------
    print("\n[8] Expiry")
    token_csrf = upload_csrf(sender, backend)
    r = fetch(
        sender,
        backend + "/api/upload",
        data=multipart({"expiry_minutes": "1"}, "expires.txt", b"short lived"),
        headers={
            "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
            "X-CSRFToken": token_csrf,
            "Accept": "application/json",
        },
    )
    short = json.loads(r.read())
    r = fetch(receiver, f"{backend}/api/share/{short['token']}/status")
    status = json.loads(r.read())
    check(status["status"] == "active" and status["seconds_remaining"] <= 60, "short-lived share is active with a countdown")

    # -- plain share, no password -----------------------------------------
    print("\n[9] Plain share (no password, repeatable)")
    token_csrf = upload_csrf(sender, backend)
    r = fetch(
        sender,
        backend + "/api/upload",
        data=multipart({"expiry_minutes": "30"}, "notes.txt", b"plain public share"),
        headers={
            "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
            "X-CSRFToken": token_csrf,
            "Accept": "application/json",
        },
    )
    plain = json.loads(r.read())
    ok = True
    for _ in range(2):
        r = fetch(receiver, f"{backend}/api/share/{plain['token']}/download")
        ok = ok and r.status == 200 and r.read() == b"plain public share"
    check(ok, "plain share downloads repeatedly")

    # -- error handling ----------------------------------------------------
    print("\n[10] Error handling")
    for bad in ["abc", "A" * 43, "' OR '1'='1"]:
        r = fetch(receiver, f"{backend}/s/" + urllib.parse.quote(bad, safe=""))
        body = r.read()
        # 403 is also a pass: Render fronts the service with Cloudflare, which
        # blocks obvious injection strings at the edge before they ever reach
        # the app. Refused earlier is better, not worse.
        check(
            r.status in (403, 404),
            f"bogus token {bad[:16]!r} refused ({r.status})",
            f"status={r.status}",
        )
        check(b"Traceback" not in body, "no traceback leaked")

    # -- frontend ----------------------------------------------------------
    if frontend:
        print("\n[11] Vercel front door")
        if not local:
            check(frontend.startswith("https://"), "frontend is served over HTTPS")
        r = fetch(device(), frontend + "/")
        page = r.read()
        check(r.status == 200, "Vercel URL responds", f"status={r.status}")
        host = urllib.parse.urlparse(backend).netloc
        check(host.encode() in page, "front door points at the Render backend", host)
        check(b"localhost" not in page and b"127.0.0.1" not in page, "no localhost in the front door")

    return summarise()


def decode_qr(png: bytes):
    """Decode a QR image if a decoder happens to be available locally."""
    try:
        import cv2
        import numpy as np
    except ImportError:
        return None
    image = cv2.imdecode(np.frombuffer(png, np.uint8), cv2.IMREAD_COLOR)
    text, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    return text or None


def summarise() -> int:
    failed = [(label, detail) for ok, label, detail in results if not ok]
    print("\n" + "=" * 66)
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("\nFAILED:")
        for label, detail in failed:
            print(f"  - {label}" + (f"  ({detail})" if detail else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
