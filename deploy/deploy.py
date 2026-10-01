"""One-command deployment of QRShare to GitHub + Render + Vercel.

    python deploy/deploy.py            # run every stage
    python deploy/deploy.py github     # or a single stage
    python deploy/deploy.py render
    python deploy/deploy.py vercel
    python deploy/deploy.py verify

Reads credentials from `.deploy.env` (gitignored). Every stage is idempotent:
re-running reuses an existing repo, database or service rather than creating a
duplicate, so a failure part way through is safe to retry.

Secret values are never printed -- only whether they are present.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "deploy"))

from render_api import RenderClient, RenderError  # noqa: E402

STATE_FILE = ROOT / ".deploy.state.json"

REQUIRED = [
    "RENDER_API_KEY",
    "VERCEL_TOKEN",
    "SECRET_KEY",
    "MASTER_ENCRYPTION_KEY",
]


# ---------------------------------------------------------------- helpers --
def say(message: str) -> None:
    print(message, flush=True)


def head(title: str) -> None:
    say(f"\n{'=' * 66}\n{title}\n{'=' * 66}")


def load_env() -> dict[str, str]:
    path = ROOT / ".deploy.env"
    if not path.exists():
        raise SystemExit("`.deploy.env` not found. Copy .deploy.env.example and fill it in.")
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()

    missing = [k for k in REQUIRED if not env.get(k)]
    if missing:
        raise SystemExit("Missing values in .deploy.env: " + ", ".join(missing))
    return env


def state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}


def save_state(**values) -> dict:
    current = state()
    current.update(values)
    STATE_FILE.write_text(json.dumps(current, indent=2), encoding="utf-8")
    return current


def run(args: list[str], check: bool = True, capture: bool = True, **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(
        args, cwd=ROOT, text=True, capture_output=capture, encoding="utf-8", errors="replace", **kwargs
    )
    if check and result.returncode != 0:
        raise SystemExit(
            f"command failed: {' '.join(args[:3])}...\n"
            f"stdout: {(result.stdout or '')[-2000:]}\nstderr: {(result.stderr or '')[-2000:]}"
        )
    return result


def gh_path() -> str:
    from shutil import which

    found = which("gh")
    if found:
        return found
    for candidate in pathlib.Path(
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Packages")
    ).glob("GitHub.cli*/bin/gh.exe"):
        return str(candidate)
    raise SystemExit("GitHub CLI not found. Install it, then run: gh auth login")


# ----------------------------------------------------------------- GitHub --
def stage_github(env: dict) -> dict:
    head("GitHub")
    gh = gh_path()

    auth = run([gh, "auth", "status"], check=False)
    if auth.returncode != 0:
        raise SystemExit(
            "GitHub CLI is not authenticated.\nRun:  gh auth login\n"
            "(GitHub.com -> HTTPS -> authenticate Git -> login with a web browser)"
        )
    user = run([gh, "api", "user", "--jq", ".login"]).stdout.strip()
    say(f"  authenticated as: {user}")

    name = env.get("GITHUB_REPO_NAME", "qrshare")
    visibility = env.get("GITHUB_REPO_VISIBILITY", "public")
    full = f"{user}/{name}"

    exists = run([gh, "repo", "view", full, "--json", "url"], check=False).returncode == 0
    if exists:
        say(f"  repository already exists: {full}")
    else:
        say(f"  creating {visibility} repository {full}")
        run([gh, "repo", "create", full, f"--{visibility}",
             "--description", "QRShare - secure QR-based temporary file sharing"])

    url = run([gh, "repo", "view", full, "--json", "url", "--jq", ".url"]).stdout.strip()

    remotes = run(["git", "remote"], check=False).stdout.split()
    if "origin" in remotes:
        run(["git", "remote", "set-url", "origin", f"{url}.git"])
    else:
        run(["git", "remote", "add", "origin", f"{url}.git"])

    # Make sure nothing secret is about to be pushed.
    tracked = run(["git", "ls-files"]).stdout.splitlines()
    for forbidden in (".env", ".deploy.env", ".deploy.state.json"):
        if forbidden in tracked:
            raise SystemExit(f"refusing to push: {forbidden} is tracked by git")

    say("  pushing main ...")
    run(["git", "push", "-u", "origin", "main"])
    say(f"  pushed: {url}")
    return save_state(github_url=url, github_repo=full, github_user=user)


# ----------------------------------------------------------------- Render --
def backend_env(env: dict, public_url: str = "") -> dict[str, str]:
    """Environment for the Render web service.

    Blobs live in Postgres (STORAGE_BACKEND=database) rather than on the
    container filesystem, which is wiped on every deploy. That keeps the whole
    deployment on free tiers with no storage provider to sign up for.
    """
    values = {
        "PYTHON_VERSION": "3.12.6",
        "FLASK_ENV": "production",
        "TRUST_PROXY": "true",
        "SESSION_COOKIE_SECURE": "true",
        "ENABLE_HSTS": "true",
        "SECRET_KEY": env["SECRET_KEY"],
        "MASTER_ENCRYPTION_KEY": env["MASTER_ENCRYPTION_KEY"],
        "STORAGE_BACKEND": "database",
        # A free Postgres plan is about 1 GB and holds the blobs as well as
        # the tables, so the per-file cap is lower than it is locally.
        "MAX_FILE_SIZE_MB": env.get("MAX_FILE_SIZE_MB", "25"),
        "DEFAULT_EXPIRY_MINUTES": "60",
        "MAX_EXPIRY_MINUTES": "1440",
        "CLEANUP_INTERVAL_SECONDS": "300",
        "CLEANUP_GRACE_MINUTES": "10",
        "RATE_LIMIT_STORAGE_URI": "memory://",
        "RATE_LIMIT_UPLOAD": "20 per hour;5 per minute",
        "RATE_LIMIT_PASSWORD": "10 per hour;5 per minute",
        "RATE_LIMIT_DOWNLOAD": "120 per hour",
        "RATE_LIMIT_STATUS": "240 per hour",
    }
    if public_url:
        # Belt and braces alongside TRUST_PROXY: pins the URL that goes into
        # every QR code, so it cannot depend on a forwarded header.
        values["PUBLIC_BASE_URL"] = public_url
    return values


BUILD_COMMAND = "pip install --upgrade pip && pip install -r requirements.txt"
START_COMMAND = (
    "gunicorn run:app --bind 0.0.0.0:$PORT --workers 1 --threads 8 "
    "--timeout 300 --access-logfile - --error-logfile -"
)


def stage_render(env: dict) -> dict:
    head("Render")
    saved = state()
    if not saved.get("github_url"):
        raise SystemExit("run the github stage first")

    client = RenderClient(env["RENDER_API_KEY"])
    owner = client.owner_id()
    say(f"  owner: {owner}")

    region = env.get("RENDER_REGION", "oregon")
    name = env.get("RENDER_SERVICE_NAME", "qrshare")

    # --- database ---------------------------------------------------------
    say("  creating/locating Postgres ...")
    database = client.create_postgres(f"{name}-db", owner, region)
    db_id = (database.get("postgres") or database).get("id") or database.get("id")
    say(f"  database id: {db_id}  (waiting until available)")
    db_url = client.postgres_connection_string(db_id)
    say("  database is ready")

    # --- web service ------------------------------------------------------
    service = client.find_service(name)
    variables = backend_env(env)
    variables["DATABASE_URL"] = db_url

    if service:
        say(f"  service already exists: {service['id']}")
        client.set_env_vars(service["id"], variables)
    else:
        say("  creating web service ...")
        created = client.create_web_service(
            name=name,
            owner=owner,
            repo=saved["github_url"],
            branch="main",
            region=region,
            build_command=BUILD_COMMAND,
            start_command=START_COMMAND,
            env_vars=variables,
        )
        service = created.get("service") or created

    service_id = service["id"]
    url = client.service_url(service) or client.service_url(client.get(f"/services/{service_id}"))
    say(f"  service id : {service_id}")
    say(f"  public URL : {url}")

    # Pin PUBLIC_BASE_URL now that the hostname is known, then deploy.
    variables["PUBLIC_BASE_URL"] = url
    client.set_env_vars(service_id, variables)

    say("  deploying (this takes a few minutes) ...")
    # Creating a service, or changing its environment, already starts a deploy.
    # Asking for another can return nothing, so fall back to whichever deploy
    # is currently running rather than treating that as a failure.
    deploy = client.trigger_deploy(service_id) or client.latest_deploy(service_id)
    deploy_id = ((deploy or {}).get("deploy") or deploy or {}).get("id")
    client.wait_for_deploy(service_id, deploy_id, on_tick=lambda s: say(f"    status: {s}"))
    say("  deploy is live")

    return save_state(render_url=url, render_service_id=service_id, render_db_id=db_id)


# ----------------------------------------------------------------- Vercel --
def stage_vercel(env: dict) -> dict:
    head("Vercel")
    saved = state()
    backend = saved.get("render_url")
    if not backend:
        raise SystemExit("run the render stage first")

    # Point the front door at the live backend.
    page = ROOT / "vercel" / "index.html"
    html = page.read_text(encoding="utf-8")
    html = re.sub(r"__BACKEND_URL__|https://[a-z0-9-]+\.onrender\.com", backend, html)
    page.write_text(html, encoding="utf-8")
    say(f"  front door now points at {backend}")

    if run(["git", "status", "--porcelain", "vercel/"], check=False).stdout.strip():
        run(["git", "add", "vercel/"])
        run(["git", "-c", "core.safecrlf=false", "commit", "-m",
             f"Point the Vercel front door at {backend}"])
        run(["git", "push", "origin", "main"])
        say("  committed and pushed")

    token = env["VERCEL_TOKEN"]
    from shutil import which

    vercel = which("vercel") or which("vercel.cmd")
    if not vercel:
        raise SystemExit("Vercel CLI not found. Install with: npm install -g vercel")

    say("  deploying static front door ...")
    result = run(
        [vercel, "deploy", "--prod", "--yes", "--token", token, "--cwd", str(ROOT / "vercel")],
        check=False,
    )
    output = (result.stdout or "") + (result.stderr or "")
    match = re.search(r"https://[a-zA-Z0-9.\-]+\.vercel\.app", output)
    if result.returncode != 0 and not match:
        raise SystemExit(f"vercel deploy failed:\n{output[-2500:]}")
    url = match.group(0) if match else ""
    say(f"  public URL : {url}")
    return save_state(vercel_url=url)


# ----------------------------------------------------------------- verify --
def stage_verify(env: dict) -> dict:
    head("Public end-to-end verification")
    saved = state()
    backend, frontend = saved.get("render_url"), saved.get("vercel_url")
    if not backend:
        raise SystemExit("nothing deployed yet")
    args = [sys.executable, str(ROOT / "deploy" / "public_e2e.py"), backend]
    if frontend:
        args.append(frontend)
    result = subprocess.run(args, cwd=ROOT)
    if result.returncode != 0:
        raise SystemExit("public end-to-end test FAILED - see the output above")
    return saved


# ------------------------------------------------------------------- main --
STAGES = {
    "github": stage_github,
    "render": stage_render,
    "vercel": stage_vercel,
    "verify": stage_verify,
}


def main(argv: list[str]) -> int:
    env = load_env()
    chosen = argv[1:] or list(STAGES)
    unknown = [s for s in chosen if s not in STAGES]
    if unknown:
        raise SystemExit(f"unknown stage(s): {unknown}. Choose from {list(STAGES)}")

    for stage in chosen:
        try:
            STAGES[stage](env)
        except RenderError as exc:
            say(f"\nRender API error during '{stage}':\n{exc}")
            return 1

    final = state()
    head("SUMMARY")
    for label, key in [
        ("GitHub  ", "github_url"),
        ("Vercel  ", "vercel_url"),
        ("Render  ", "render_url"),
    ]:
        say(f"  {label}: {final.get(key, '(not deployed)')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
