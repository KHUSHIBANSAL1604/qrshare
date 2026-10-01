# QRShare — Secure QR-Based Temporary File Sharing

Upload a file, choose how long the link should live, and get a QR code that a
phone camera can read. Every file is encrypted at rest with its own key, links
expire, and a share can require a password or self-destruct after one download.

> **The QR code is not the security boundary.** It is a convenient way to move
> a URL from a screen to a camera. Anyone who photographs the code has the
> link. What protects the file is the unpredictable token behind it, plus
> expiry, the optional password, one-time consumption, and rate limiting.

---

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Installation](#installation)
- [Environment setup](#environment-setup)
- [Running locally](#running-locally)
- [Scanning from a phone](#scanning-from-a-phone)
- [Database](#database)
- [File storage](#file-storage)
- [Security model](#security-model)
- [API endpoints](#api-endpoints)
- [Testing](#testing)
- [Docker](#docker)
- [Project structure](#project-structure)
- [Example usage](#example-usage)
- [Demo script](#demo-script)
- [Limitations](#limitations)
- [Future enhancements](#future-enhancements)

---

## Features

| | |
|---|---|
| **Encrypted at rest** | AES-256-GCM, a fresh key per file, that key wrapped under a server master key |
| **Expiring links** | 10 minutes to 24 hours (configurable), enforced on every access |
| **Password protection** | Argon2id hashing, server-side verification, rate limited |
| **One-time downloads** | Consumed atomically — concurrent requests cannot both win |
| **QR codes** | Generated server-side, inline on the share page, downloadable as PNG |
| **Rate limiting** | Separate budgets for upload, download, password attempts and status polls |
| **Audit logging** | Views, downloads, failed passwords, deletions — never secrets |
| **Automatic cleanup** | Background sweep removes expired shares, consumed files and orphan blobs |
| **Sender dashboard** | Live countdown, download count, activity log, cancel button |
| **No accounts** | Nothing to sign up for, no email address, no tracking |

---

## Architecture

```
Browser (sender)                    Flask application                Disk
────────────────                    ─────────────────                ────
 upload.js
   │ XHR multipart  ──────────►  POST /api/upload
   │                              │
   │                              ├─ validate_upload()      size / extension / name
   │                              ├─ FileService.store()
   │                              │    ├─ EncryptionService
   │                              │    │    ├─ random 256-bit data key
   │                              │    │    ├─ AES-256-GCM framed stream ──►  <random>.enc
   │                              │    │    └─ wrap key under master key ──►  DB column
   │                              │    └─ LocalStorageBackend.save()
   │                              ├─ ShareService.create_share()
   │                              │    ├─ token       = secrets.token_urlsafe(32)
   │                              │    ├─ owner_token = secrets.token_urlsafe(32)
   │                              │    └─ password_hash = Argon2id (optional)
   │                              └─ AuditService.record()
   │ ◄── 201 {token, manage_url}
   ▼
 /share/<token>   ── QR + live status + cancel  (owner only)


Browser (receiver)
──────────────────
 scans QR ─►  GET /s/<token>          renders state, never the file
                  │
                  ├─ password?  ─► POST /api/share/<token>/verify-password
                  │                    └─ Argon2id verify ─► signed 5-min ticket
                  │
                  └─ GET /api/share/<token>/download?ticket=…
                       ├─ 1. assert_downloadable()   expiry / used / deleted
                       ├─ 2. verify_ticket()         password gate
                       ├─ 3. claim_download()        atomic UPDATE … WHERE used = 0
                       └─ 4. stream decrypted frames ─► attachment
```

The ordering in step 3 is deliberate: the share is **claimed before any byte is
streamed**, which is what makes a one-time link impossible to serve twice.

### Layering

Route handlers are thin. All business rules live in `app/services/`:

| Service | Responsibility |
|---|---|
| `EncryptionService` | Data keys, key wrapping, framed AES-256-GCM streams |
| `StorageBackend` | `save` / `open` / `delete` / `exists` — `LocalStorageBackend` today, S3 tomorrow |
| `FileService` | Encrypt-on-write, decrypt-on-read, blob lifecycle |
| `ShareService` | Tokens, expiry, password checks, tickets, atomic consumption |
| `QRCodeService` | PNG and data-URI rendering |
| `AuditService` | Append-only security event log |
| `CleanupService` | Shredding, row purging, orphan collection |

They are wired once into a `ServiceRegistry` on `app.extensions["qrshare"]`,
so swapping an implementation in a test is a one-line change.

---

## Technology stack

| Layer | Choice | Why |
|---|---|---|
| Web | Flask 3 | Small enough to read end to end; server-rendered pages need no SPA |
| ORM | SQLAlchemy 2 / Flask-SQLAlchemy | Parameterised queries by construction; swap SQLite → Postgres via one URL |
| Database | SQLite | Zero setup for an MVP; no SQLite-specific SQL anywhere |
| Crypto | `cryptography` (AES-256-GCM) | Authenticated encryption from a maintained, audited library |
| Passwords | `argon2-cffi` (Argon2id) | Memory-hard; falls back to Werkzeug scrypt if unavailable |
| CSRF | Flask-WTF | Protects every state-changing browser endpoint |
| Rate limiting | Flask-Limiter | Per-endpoint budgets, configurable, pluggable storage |
| Tickets | `itsdangerous` | Already a Flask dependency; signed, expiring tokens |
| QR | `qrcode` + `Pillow` | Standard, well-tested, no service call |
| Frontend | Hand-written HTML/CSS/JS | ~700 lines total; a framework would add weight, not capability |

No Redis, no Celery, no build step.

---

## Installation

**Requires Python 3.11 or newer.**

```bash
git clone <your-repo-url> qrshare
cd qrshare

python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

---

## Environment setup

```bash
cp .env.example .env        # Windows: copy .env.example .env
python manage.py keygen     # prints a fresh SECRET_KEY and MASTER_ENCRYPTION_KEY
```

Paste both values into `.env`. `.env` is gitignored — **never commit it**.

| Variable | Default | Meaning |
|---|---|---|
| `FLASK_ENV` | `production` | `development` / `testing` / `production` |
| `SECRET_KEY` | — | Signs sessions, CSRF tokens and download tickets. **Required.** |
| `MASTER_ENCRYPTION_KEY` | — | Base64 32 bytes; wraps every per-file key. **Required.** |
| `DATABASE_URL` | `sqlite:///instance/qrshare.db` | Any SQLAlchemy URL |
| `STORAGE_PATH` | `./storage` | Where encrypted blobs live (outside the web root) |
| `MAX_FILE_SIZE_MB` | `100` | Upload limit |
| `ALLOWED_EXTENSIONS` | *(empty)* | If set, an allowlist — nothing else is accepted |
| `BLOCKED_EXTENSIONS` | executables | Used only when no allowlist is configured |
| `DEFAULT_EXPIRY_MINUTES` | `60` | Pre-selected expiry |
| `MAX_EXPIRY_MINUTES` | `1440` | Ceiling on requested expiry |
| `CLEANUP_GRACE_MINUTES` | `10` | How long a dead share is kept so receivers still see *why* |
| `CLEANUP_INTERVAL_SECONDS` | `300` | Background sweep interval; `0` disables it |
| `RATE_LIMIT_UPLOAD` | `10 per hour;3 per minute` | Flask-Limiter syntax, `;`-separated |
| `RATE_LIMIT_PASSWORD` | `10 per hour;5 per minute` | Brute-force budget |
| `RATE_LIMIT_DOWNLOAD` | `60 per hour` | |
| `RATE_LIMIT_STORAGE_URI` | `memory://` | Per-process; use `redis://…` for multiple workers |
| `PUBLIC_BASE_URL` | *(derived)* | Base URL embedded in the QR — set this behind a proxy |
| `ENABLE_HSTS` | `false` | Only turn on with real TLS in front |
| `SESSION_COOKIE_SECURE` | `false` | Turn on with real TLS |

> ⚠️ Losing or changing `MASTER_ENCRYPTION_KEY` makes **every stored file
> permanently unreadable**. There is no recovery path by design.

In `FLASK_ENV=development` a missing secret is generated at startup with a loud
warning, so you can try the app immediately — but every restart invalidates
existing shares. Any other environment refuses to start without real secrets.

---

## Running locally

```bash
python run.py
```

Then open <http://127.0.0.1:5000>.

Maintenance commands:

```bash
python manage.py keygen     # print fresh secrets
python manage.py init-db    # create tables
python manage.py cleanup    # one cleanup sweep (good for cron)
python manage.py stats      # counts by share status
```

---

## Scanning from a phone

`127.0.0.1` means nothing to your phone, so the QR must carry your machine's
LAN address:

1. Find your IP — `ipconfig` (Windows) or `ifconfig` / `ip addr` (macOS/Linux).
2. In `.env`, set `PUBLIC_BASE_URL=http://192.168.1.42:5000` (your address).
3. Start with `HOST=0.0.0.0 PORT=5000 python run.py`.
4. Make sure laptop and phone are on the same Wi-Fi.

The receiver needs no app — any phone camera and browser will do.

---

## Database

Three tables, created automatically on first run.

```
files                         shares                        audit_logs
─────                         ──────                        ──────────
id            PK              id              PK            id            PK
original_filename             file_id         FK → files    share_id      FK → shares
stored_filename  UNIQUE       token           UNIQUE idx    event_type    idx
storage_backend               owner_token     UNIQUE idx    timestamp
mime_type                     created_at                    ip_address
size                          expires_at      idx           user_agent
encrypted_file_key            password_hash                 success
uploaded_at                   one_time                      reason
                              used
     1 ──────── N             downloads          1 ──────── N
                              deleted_at      idx
                              last_accessed_at
```

Both foreign keys cascade on delete, and the SQLite `foreign_keys` pragma is
enabled on every connection so those cascades actually fire — without it
SQLite silently ignores them and deleted shares leave orphaned audit rows.

`Share.status` is a **derived** property (`ACTIVE` / `EXPIRED` / `USED` /
`DELETED`), computed from timestamps and flags. It is never stored, never sent
by the client, and never trusted from anywhere but the server.

### Moving to PostgreSQL / MySQL

Change `DATABASE_URL` and install the driver. No raw SQL, no SQLite-specific
types, and the one conditional `UPDATE` used for atomic consumption is standard
SQL that works better under a real MVCC engine, not worse.

---

## File storage

```
storage/
├── 3f9ac1d0e4b27856f1a0c9d2e7b48a3c5d6e1f20.enc
└── 8b2e7d1c9a0f3e5b6d4c2a1f8e7b3d5c9a0e2f14.enc
```

- Names are **random**, generated by the storage backend — never derived from
  the uploaded filename.
- The directory sits outside `app/static`, so nothing here is routable.
- Keys are validated against a strict `^[0-9a-f]{16,64}\.enc$` pattern *and*
  re-checked to resolve inside the storage root before any filesystem call.
- Writes go to a temp file and are atomically renamed, so a crash mid-upload
  never leaves a truncated blob under a live key.

### Blob format

```
header : "QRS1" | nonce_prefix(8) | chunk_size(4, big endian)
frame* : ct_len(4, big endian) | ciphertext | tag(16)

nonce  = nonce_prefix || frame_index(4, big endian)              (12 bytes)
AAD    = "QRS1" | nonce_prefix | frame_index(4) | final_flag(1)
```

Frames are 1 MiB of plaintext each. Because the frame index is authenticated,
frames cannot be reordered, duplicated or dropped; because the final frame is
flagged, the file cannot be truncated undetected. Each frame is verified
*before* its plaintext is yielded, so a tampered blob raises instead of
streaming unauthenticated bytes to the client.

This is also why memory stays flat: a 90 MB download grew the server's resident
memory by 1.4 MB in testing, because only one frame is ever in RAM.

---

## Security model

### Encryption

```
plaintext ──► AES-256-GCM (random per-file key) ──► <random>.enc on disk
                    │
 per-file key ──► AES-256-GCM (master key from env) ──► DB column
```

A database dump alone reveals nothing. A stolen blob alone reveals nothing.
An attacker needs the database *and* the master key, and the master key never
touches the database or source control.

### What actually protects a link

| Control | Implementation |
|---|---|
| Unpredictable token | `secrets.token_urlsafe(32)` — 256 bits from the OS CSPRNG. No counters, timestamps or filename hashes |
| Expiry | Checked on every access; `410 Gone` afterwards |
| Password | Argon2id, server-side; verification runs even for unprotected shares so timing reveals nothing |
| One-time use | `UPDATE shares SET used=1 WHERE id=? AND used=0` — claimed before streaming |
| Rate limiting | Per-endpoint budgets on upload, download, password and status |
| Owner separation | A second `owner_token` gates the manage page and cancel; it is never in the QR |

### Implemented defences

- **Path traversal** — filenames never form a path; storage keys are pattern-checked and root-confined.
- **SQL injection** — SQLAlchemy parameterised queries throughout; tokens are shape-validated before lookup.
- **XSS** — Jinja autoescaping, filename sanitisation strips `< > " \ /` and control characters, and a CSP with **no** `unsafe-inline`. Every script is external or carries a per-request nonce; no page uses a `style=` attribute.
- **CSRF** — Flask-WTF on every state-changing endpoint.
- **Malicious uploads** — size cap, executable-extension denylist (or a strict allowlist), random storage names, storage outside the web root. Downloads are *always* `application/octet-stream` + `attachment` + `nosniff`, so an uploaded `.html` can never execute on this origin.
- **Enumeration** — unknown, malformed and unauthorised tokens all return an identical `404`.
- **Information leakage** — no stack traces, paths, SQL or internal ids reach the client; tracebacks go to the log.

### Response headers

`Content-Security-Policy` (nonce-based, no `unsafe-inline`/`unsafe-eval`),
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: same-origin`, `Permissions-Policy`, and `Cache-Control:
no-store` on every share and API path.

`Strict-Transport-Security` is sent **only** when `ENABLE_HSTS=true` *and* the
request arrived over TLS. Advertising HTTPS you do not have would lock users
out of a plain-HTTP deployment.

---

## API endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Landing page |
| `GET` | `/upload` | Upload form |
| `GET` | `/security` | Security model, including its limits |
| `GET` | `/healthz` | Liveness probe |
| `POST` | `/api/upload` | Encrypt, store, create a share |
| `GET` | `/s/<token>` | Receiver page (renders state — never the file) |
| `GET` | `/share/<token>` | Sender's manage page (**owner token required**) |
| `GET` | `/api/share/<token>/status` | Public status; owner fields when authorised |
| `POST` | `/api/share/<token>/verify-password` | Exchange a password for a 5-minute ticket |
| `GET` | `/api/share/<token>/download` | Stream the decrypted file |
| `GET` | `/api/qr/<token>` | QR PNG (`?download=1` for an attachment) |
| `POST` | `/api/share/<token>/cancel` | Revoke early (**owner token required**) |

### Status response

```json
{
  "ok": true,
  "status": "active",
  "filename": "quarterly-report.pdf",
  "size": 4718592,
  "expires_at": "2026-09-13T15:42:00+00:00",
  "seconds_remaining": 3421,
  "downloads": 0,
  "one_time": true,
  "password_protected": true
}
```

Database ids, storage paths, the owner token and the password hash are never
included.

### Status codes

`200` ok · `201` created · `400` validation / CSRF · `401` password required or
wrong · `404` unknown token *or* unauthorised · `410` expired, used or
cancelled · `413` too large · `429` rate limited.

---

## Testing

```bash
pytest              # whole suite
pytest -v           # per-test names
pytest tests/test_security.py
```

**173 tests, all passing** (~49s — Argon2 is intentionally slow).

| File | Tests | Covers |
|---|---|---|
| `test_encryption.py` | 23 | Round trips across frame boundaries, key isolation, wrong keys, bit flips, truncation, frame reordering, key wrapping |
| `test_upload.py` | 17 | Valid/empty/oversized/blocked uploads, encrypted-at-rest verification, random storage names, hashed passwords, auditing |
| `test_share.py` | 22 | Token uniqueness and URL-safety, receiver page, status scoping, manage-page authorisation, QR output, cancellation |
| `test_download.py` | 15 | Byte-exact round trip, safe headers, download counting, one-time semantics, **8-thread concurrency race**, missing blobs |
| `test_password.py` | 19 | Salted hashing, ticket issue/verify/expiry, cross-share ticket rejection, enumeration resistance |
| `test_expiry.py` | 11 | Boundary conditions, enforcement on every path, tz round-tripping, the expired page |
| `test_security.py` | 25 | Path traversal, XSS, SQL injection, token guessing, headers, CSRF, live rate limiting, error leakage |
| `test_cleanup.py` | 12 | Shredding, grace windows, orphan blobs, row purging, idempotency |
| `test_flow.py` | 11 | Full demo flow end to end, page smoke tests, per-page CSP compliance |

Two tests deserve a mention at a viva:

- **`test_concurrent_one_time_downloads_consume_exactly_once`** fires eight
  real threads, each with its own client and database connection, through a
  barrier at the same one-time link. Exactly one gets `200`; the share ends
  with `used=True, downloads=1`.
- **`test_every_page_passes_its_own_csp`** parses each rendered page and
  asserts every `<script>` carries `src=` or that request's nonce, and that no
  `style=` attribute exists — so the CSP can never be quietly weakened.

---

## Docker

```bash
docker build -t qrshare .
docker run -p 8000:8000 --env-file .env \
  -v qrshare-storage:/data/storage \
  -v qrshare-db:/data/db \
  qrshare
```

Runs as a non-root user. Both volumes are required — losing either one makes
existing shares unusable.

The image runs **one** gunicorn worker with eight threads on purpose: the
default rate limiter and the cleanup scheduler are per-process. Before scaling
to multiple workers, point `RATE_LIMIT_STORAGE_URI` at a shared store.

---

## Project structure

```
qrshare/
├── app/
│   ├── __init__.py            application factory, logging, CLI
│   ├── config.py              every tunable, read from the environment once
│   ├── extensions.py          db / csrf / limiter singletons, SQLite pragmas
│   ├── security.py            CSP nonce + security headers
│   ├── errors.py              friendly pages, JSON for XHR, no leakage
│   ├── models/
│   │   ├── file.py            StoredFile
│   │   ├── share.py           Share + derived ShareStatus
│   │   └── audit.py           AuditLog + AuditEvent
│   ├── routes/
│   │   ├── __init__.py        share URLs, owner-token session helpers
│   │   ├── main.py            landing / upload / security / health
│   │   ├── share.py           /s/<token> and /share/<token>
│   │   └── api.py             JSON API + the download stream
│   ├── services/
│   │   ├── encryption_service.py   framed AES-256-GCM, key wrapping
│   │   ├── storage/                backend interface + local implementation
│   │   ├── file_service.py         encrypt-on-write, decrypt-on-read
│   │   ├── share_service.py        tokens, tickets, atomic consumption
│   │   ├── qr_service.py           PNG / data-URI QR codes
│   │   ├── audit_service.py        security event log
│   │   └── cleanup_service.py      shredding, purging, orphan collection
│   ├── utils/
│   │   ├── validation.py      filename sanitising, upload/expiry/password rules
│   │   ├── passwords.py       Argon2id with a scrypt fallback
│   │   └── formatting.py      sizes, durations, RFC 5987 Content-Disposition
│   ├── templates/             base, index, upload, share, download, security, errors
│   └── static/css|js|img      one stylesheet, four scripts, one favicon
├── storage/                   encrypted blobs (gitignored)
├── instance/                  SQLite database (gitignored)
├── tests/                     173 tests
├── run.py                     development entry point
├── manage.py                  keygen / cleanup / init-db / stats
├── requirements.txt
├── Dockerfile
├── pytest.ini
├── .env.example
└── .gitignore
```

No `migrations/` directory: the schema is created with `db.create_all()`, which
is honest for a project that has never shipped a migration. Adding Alembic is a
one-command change when the schema first needs to evolve in place.

---

## Example usage

**Sender**

1. Open `/upload`, drag in `quarterly-report.pdf`.
2. Expiry `10 minutes`, password on, one-time on.
3. Press **Encrypt & create QR code** — a progress bar runs, then the manage
   page opens with the QR, a live countdown and a download counter.

**Receiver**

4. Points a phone camera at the code, taps the notification.
5. Sees the filename, size, expiry and a **one-time link** warning.
6. Types the password, taps **Unlock & download**, the file downloads.
7. Reloading shows **Already used**.

**Command line**

```bash
# Upload (CSRF token comes from the /upload page)
curl -c jar -b jar -s http://localhost:5000/upload \
  | grep -oP 'name="csrf_token" value="\K[^"]+' > token.txt

curl -c jar -b jar -X POST http://localhost:5000/api/upload \
  -H "X-CSRFToken: $(cat token.txt)" \
  -F "file=@report.pdf" -F "expiry_minutes=60" -F "one_time=true"

# Status and download
curl -s http://localhost:5000/api/share/<token>/status
curl -OJ http://localhost:5000/api/share/<token>/download
```

---

## Demo script

| # | Action | Expected |
|---|---|---|
| 1 | Open QRShare on the laptop | Landing page |
| 2 | Choose `sample.pdf` | Name, size and type appear |
| 3 | Password on, one-time on, expiry 10 min | Password fields expand |
| 4 | Upload | Progress bar, then the share page |
| 5 | Show the QR | Rendered inline, downloadable |
| 6 | Scan with a phone | Secure file page, no file yet |
| 7 | — | Password prompt shown |
| 8 | Enter the password | Ticket issued, download starts |
| 9 | — | File arrives intact |
| 10 | Scan again | **"Already used"** |
| 11 | Upload with a 1-minute expiry and wait | **"Share expired"** |

Worth showing alongside it: `python manage.py stats`, the **Activity** list on
the manage page, and `ls storage/` — random `.enc` names whose contents contain
none of the original text.

---

## Limitations

Stated plainly, because a security claim that is not true is worse than no
claim at all.

1. **This is not end-to-end encryption.** The server holds the master key, so a
   compromised server can read files. Real E2EE would keep the key in the URL
   fragment, where it never reaches the server — at the cost of the server
   being unable to enforce anything about it.
2. **Transport security is the deployment's job.** `python run.py` serves plain
   HTTP. On a LAN, a share link and password are visible to anyone on the
   network. Put TLS in front before this leaves localhost.
3. **An interrupted one-time download still counts as used.** The share is
   claimed before streaming starts, which is exactly what makes the race
   impossible. Failing closed is the right direction for a single-use promise.
4. **Rate limiting is per process by default.** `memory://` counters are not
   shared between workers. Use Redis for a multi-worker deployment.
5. **Cleanup runs in-process.** A daemon thread, so it stops when the app stops.
   For guaranteed sweeps use `python manage.py cleanup` from cron and set
   `CLEANUP_INTERVAL_SECONDS=0`.
6. **No malware scanning.** Uploads are treated as untrusted bytes and always
   served as attachments, never executed — but nothing inspects them.
7. **Deleted files are unlinked, not shredded.** On an SSD, `unlink` does not
   guarantee the blocks are gone. The encryption is what makes the remnants
   useless.
8. **SQLite limits write concurrency.** Fine for a demo and a small deployment;
   move to PostgreSQL for real traffic.
9. **The manage link is itself a bearer credential.** Anyone holding it can
   cancel the share. `Referrer-Policy: same-origin` keeps it out of outbound
   requests, but it should be treated like a password.

---

## Future enhancements

Deliberately **not** built, with the seams left in place:

- **User accounts** — `Share` would gain a nullable `user_id`; nothing else changes.
- **S3 / object storage** — implement `StorageBackend`'s four methods; `storage_backend` is already a column.
- **End-to-end encryption** — derive the key in the browser, carry it in the URL fragment.
- **Virus scanning** — a hook between `validate_upload()` and `FileService.store()`.
- **Email / SMS notification** — on the `DOWNLOAD_SUCCESS` audit event.
- **Admin dashboard** — the audit log already holds everything it would show.
- **OTP instead of a password** — a second `ShareService` credential strategy.
- **Redis-backed limits and Celery cleanup** — configuration, not a rewrite.

---

## License

Provided as-is for educational use.
