"""Development entry point.

    python run.py

For production use a real WSGI server instead, e.g.::

    waitress-serve --port 8000 "app:create_app('production')"
    gunicorn "app:create_app('production')" -b 0.0.0.0:8000
"""
from __future__ import annotations

import os

from werkzeug.middleware.proxy_fix import ProxyFix

from app import create_app

app = create_app()

# Behind a reverse proxy this makes request.remote_addr (and therefore the
# rate limiter) reflect the real client rather than the proxy. Harmless when
# there is no proxy, because no X-Forwarded-* headers arrive.
if os.environ.get("TRUST_PROXY", "").lower() in {"1", "true", "yes"}:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    print(f"\n  QRShare running at http://{host}:{port}\n")
    print("  To scan the QR from a phone, start with HOST=0.0.0.0 and set")
    print("  PUBLIC_BASE_URL to your machine's LAN address in .env.\n")
    app.run(host=host, port=port, debug=app.config["DEBUG"])
