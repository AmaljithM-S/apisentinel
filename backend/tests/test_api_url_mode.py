"""HTTP-level integration tests for URL-based scanning: register, create a
url-mode project, confirm authorization, start a scan, read results back —
through the real FastAPI app and a real database, the way the dashboard does.

Requires a real Postgres DATABASE_URL (see test_scan_service_url_mode.py for
why); skipped automatically otherwise.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

if "sqlite" in os.environ.get("DATABASE_URL", "sqlite://"):
    pytest.skip("requires a real Postgres DATABASE_URL", allow_module_level=True)

from fastapi.testclient import TestClient  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def vulnapi_server(tmp_path_factory):
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    from app.config import settings

    previous = settings.runtime_target_allowlist
    settings.runtime_target_allowlist = f"{previous},127.0.0.1:{port}"

    db_path = tmp_path_factory.mktemp("vulnapi") / "vulnapi.db"
    env = dict(os.environ)
    env["VULNAPI_DB"] = str(db_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "targets.vulnapi.app:app", "--app-dir", str(REPO_ROOT),
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(REPO_ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 15
        up = False
        while time.monotonic() < deadline:
            try:
                httpx.get(f"{base_url}/openapi.json", timeout=1)
                up = True
                break
            except httpx.HTTPError:
                time.sleep(0.25)
        if not up:
            proc.kill()
            pytest.skip("Could not start the bundled vulnapi target.")
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        settings.runtime_target_allowlist = previous


@pytest.fixture()
def client():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(os.environ["DATABASE_URL"], future=True)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)

    def _override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture()
def auth_headers(client):
    email = f"api-test-{uuid.uuid4().hex[:10]}@apisentinel-pytest.com"
    resp = client.post("/api/auth/register", json={"email": email, "password": "a-strong-password-123"})
    assert resp.status_code == 201, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_create_url_mode_project_without_artifacts(client, auth_headers, vulnapi_server):
    resp = client.post(
        "/api/projects",
        headers=auth_headers,
        json={
            "name": "Black-box test project",
            "scan_mode": "url",
            "runtime_base_url": vulnapi_server,
            "target_authorized": True,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["scan_mode"] == "url"
    assert body["target_authorized"] is True
    assert body["authorization_method"] == "manual"
    assert body["authorization_token"]  # present so /authorization/verify can be used later
    assert body["artifacts"] == []


def test_url_mode_project_requires_target_url(client, auth_headers):
    resp = client.post(
        "/api/projects",
        headers=auth_headers,
        json={"name": "Missing target", "scan_mode": "url"},
    )
    assert resp.status_code == 422


def test_scan_without_artifacts_or_url_is_rejected(client, auth_headers):
    resp = client.post(
        "/api/projects", headers=auth_headers, json={"name": "Empty source-mode project"}
    )
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = client.post(f"/api/projects/{project_id}/scans", headers=auth_headers, json={})
    assert resp.status_code == 422
    assert "source file" in resp.json()["detail"].lower()


def test_scan_rejected_when_target_not_authorized(client, auth_headers):
    # A loopback address, but neither "localhost" nor "127.0.0.1" textually —
    # so it does not match the default RUNTIME_TARGET_ALLOWLIST entries, and
    # with target_authorized left False it must be rejected before any
    # request is sent (no server needs to be listening there for this check).
    resp = client.post(
        "/api/projects",
        headers=auth_headers,
        json={
            "name": "Not authorized yet",
            "scan_mode": "url",
            "runtime_base_url": "http://127.0.0.2:9",
            "target_authorized": False,
        },
    )
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = client.post(f"/api/projects/{project_id}/scans", headers=auth_headers, json={})
    assert resp.status_code == 403, resp.text


def test_authorization_confirm_endpoint(client, auth_headers, vulnapi_server):
    resp = client.post(
        "/api/projects",
        headers=auth_headers,
        json={"name": "Confirm later", "scan_mode": "url", "runtime_base_url": vulnapi_server},
    )
    project_id = resp.json()["id"]
    assert resp.json()["target_authorized"] is False

    resp = client.post(
        f"/api/projects/{project_id}/authorization/confirm",
        headers=auth_headers,
        json={"confirm": True, "statement": "I own this test target"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["target_authorized"] is True
    assert body["authorization_method"] == "manual"
    assert body["authorization_confirmed_at"] is not None


def test_authorization_confirm_requires_true(client, auth_headers, vulnapi_server):
    resp = client.post(
        "/api/projects",
        headers=auth_headers,
        json={"name": "Refuse confirm", "scan_mode": "url", "runtime_base_url": vulnapi_server},
    )
    project_id = resp.json()["id"]
    resp = client.post(
        f"/api/projects/{project_id}/authorization/confirm",
        headers=auth_headers,
        json={"confirm": False},
    )
    assert resp.status_code == 422


def test_full_url_scan_via_http_api_confirms_bola(client, auth_headers, vulnapi_server):
    resp = client.post(
        "/api/projects",
        headers=auth_headers,
        json={
            "name": "Full HTTP scan",
            "scan_mode": "url",
            "runtime_base_url": vulnapi_server,
            "target_authorized": True,
            "runtime_credentials": {
                "login_path": "/login",
                "login_style": "json",
                "identifier_field": "email",
                "token_field": "access_token",
                "users": [
                    {"label": "alice", "email": "alice@vulnshop.test", "password": "alice-password", "object_id": "1001"},
                    {"label": "bob", "email": "bob@vulnshop.test", "password": "bob-password", "object_id": "1002"},
                ],
            },
        },
    )
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    resp = client.post(
        f"/api/projects/{project_id}/scans",
        headers=auth_headers,
        json={"run_static": True, "run_llm": False, "run_runtime": True},
    )
    assert resp.status_code == 202, resp.text
    scan_id = resp.json()["id"]

    deadline = time.monotonic() + 30
    status_value = "queued"
    while time.monotonic() < deadline:
        resp = client.get(f"/api/scans/{scan_id}", headers=auth_headers)
        status_value = resp.json()["status"]
        if status_value in {"completed", "failed"}:
            break
        time.sleep(0.5)
    assert status_value == "completed", resp.json()

    resp = client.get(f"/api/scans/{scan_id}/findings", headers=auth_headers)
    assert resp.status_code == 200
    findings = resp.json()
    bola = [
        f for f in findings
        if f["owasp_category"] == "API1" and f["path"] == "/orders/{order_id}" and f["evidence_level"] == "confirmed"
    ]
    assert bola, [f["evidence_level"] for f in findings]

    resp = client.get(f"/api/projects/{project_id}/endpoints", headers=auth_headers)
    assert resp.status_code == 200
    endpoints = resp.json()
    assert any(e["discovered_via"] == "web" for e in endpoints)
