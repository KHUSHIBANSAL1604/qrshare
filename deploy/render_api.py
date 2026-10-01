"""Minimal Render REST API client.

Only the handful of calls the deployment needs. Uses the standard library so
the deployment tooling adds no dependency to the application itself.

Every failure carries the server's own response body, because a Render error
is usually specific ("plan not available in region", "name already taken")
and guessing from a bare status code wastes a deploy cycle.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

API = "https://api.render.com/v1"


class RenderError(RuntimeError):
    """An API call Render refused. Carries status and body for diagnosis."""

    def __init__(self, status: int, body: str, context: str = "") -> None:
        super().__init__(f"Render API {status} during {context or 'request'}: {body[:800]}")
        self.status = status
        self.body = body


class RenderClient:
    def __init__(self, api_key: str) -> None:
        if not api_key:
            raise RenderError(0, "missing API key", "init")
        self._key = api_key

    # -- transport ---------------------------------------------------------
    def _request(self, method: str, path: str, payload: Any = None) -> Any:
        url = path if path.startswith("http") else API + path
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Authorization", f"Bearer {self._key}")
        request.add_header("Accept", "application/json")
        if data:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                raw = response.read().decode() or "null"
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            raise RenderError(exc.code, exc.read().decode(errors="replace"), f"{method} {path}") from None

    get = lambda self, p: self._request("GET", p)  # noqa: E731
    post = lambda self, p, b: self._request("POST", p, b)  # noqa: E731
    put = lambda self, p, b: self._request("PUT", p, b)  # noqa: E731
    patch = lambda self, p, b: self._request("PATCH", p, b)  # noqa: E731

    # -- account -----------------------------------------------------------
    def owner_id(self) -> str:
        owners = self.get("/owners?limit=20")
        if not owners:
            raise RenderError(0, "no owners returned for this API key", "owners")
        first = owners[0]
        return (first.get("owner") or first)["id"]

    # -- lookups -----------------------------------------------------------
    def find_service(self, name: str) -> dict | None:
        for item in self.get(f"/services?name={name}&limit=20") or []:
            service = item.get("service") or item
            if service.get("name") == name:
                return service
        return None

    def find_postgres(self, name: str) -> dict | None:
        for item in self.get(f"/postgres?name={name}&limit=20") or []:
            database = item.get("postgres") or item
            if database.get("name") == name:
                return database
        return None

    # -- database ----------------------------------------------------------
    def create_postgres(
        self, name: str, owner: str, region: str, plan: str = "free", version: str = "16"
    ) -> dict:
        existing = self.find_postgres(name)
        if existing:
            return existing
        return self.post(
            "/postgres",
            {
                "name": name,
                "ownerId": owner,
                "plan": plan,
                "region": region,
                # Render requires an explicit major version.
                "version": version,
                "databaseName": "qrshare",
                "databaseUser": "qrshare",
            },
        )

    def postgres_connection_string(self, postgres_id: str, timeout: int = 600) -> str:
        """Wait for the database to become available and return its URL.

        A new instance reports `creating` for a minute or two; asking for the
        connection string before then returns nothing useful.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            info = self.get(f"/postgres/{postgres_id}/connection-info")
            url = info.get("internalConnectionString") or info.get("externalConnectionString")
            if url:
                return url
            time.sleep(10)
        raise RenderError(0, "database did not become available in time", "postgres wait")

    # -- web service -------------------------------------------------------
    def create_web_service(
        self,
        *,
        name: str,
        owner: str,
        repo: str,
        branch: str,
        region: str,
        build_command: str,
        start_command: str,
        env_vars: dict[str, str],
        health_check_path: str = "/healthz",
        plan: str = "free",
    ) -> dict:
        return self.post(
            "/services",
            {
                "type": "web_service",
                "name": name,
                "ownerId": owner,
                "repo": repo,
                "branch": branch,
                "autoDeploy": "yes",
                "serviceDetails": {
                    "env": "python",
                    "region": region,
                    "plan": plan,
                    "healthCheckPath": health_check_path,
                    "envSpecificDetails": {
                        "buildCommand": build_command,
                        "startCommand": start_command,
                    },
                },
                "envVars": [{"key": k, "value": v} for k, v in env_vars.items()],
            },
        )

    def set_env_vars(self, service_id: str, env_vars: dict[str, str]) -> Any:
        """Replace the service's environment. Triggers a redeploy."""
        return self.put(
            f"/services/{service_id}/env-vars",
            [{"key": k, "value": v} for k, v in env_vars.items()],
        )

    def get_env_vars(self, service_id: str) -> dict[str, str]:
        out = {}
        for item in self.get(f"/services/{service_id}/env-vars?limit=100") or []:
            var = item.get("envVar") or item
            out[var["key"]] = var.get("value", "")
        return out

    def trigger_deploy(self, service_id: str, clear_cache: bool = False) -> dict:
        return self.post(
            f"/services/{service_id}/deploys",
            {"clearCache": "clear" if clear_cache else "do_not_clear"},
        )

    def latest_deploy(self, service_id: str) -> dict | None:
        items = self.get(f"/services/{service_id}/deploys?limit=1")
        if not items:
            return None
        return items[0].get("deploy") or items[0]

    def wait_for_deploy(
        self, service_id: str, deploy_id: str | None = None, timeout: int = 1500, on_tick=None
    ) -> dict:
        """Poll until the deploy reaches a terminal state.

        Render's terminal states are `live` (good) and several failure modes;
        anything else means still working.
        """
        terminal_ok = {"live"}
        terminal_bad = {"build_failed", "update_failed", "canceled", "deactivated", "pre_deploy_failed"}
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            deploy = (
                self.get(f"/services/{service_id}/deploys/{deploy_id}")
                if deploy_id
                else self.latest_deploy(service_id)
            )
            if deploy:
                deploy = deploy.get("deploy") or deploy
                status = deploy.get("status", "")
                if status != last and on_tick:
                    on_tick(status)
                    last = status
                if status in terminal_ok:
                    return deploy
                if status in terminal_bad:
                    raise RenderError(0, f"deploy finished as {status}: {json.dumps(deploy)[:600]}", "deploy")
            time.sleep(10)
        raise RenderError(0, "deploy did not finish within the timeout", "deploy wait")

    def service_url(self, service: dict) -> str:
        details = service.get("serviceDetails") or {}
        url = details.get("url") or service.get("url") or ""
        if url and not url.startswith("http"):
            url = "https://" + url
        return url
