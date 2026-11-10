"""End-to-end test of ``execute_scan`` for a URL-mode project.

Runs the complete database-backed pipeline exactly as a real deployment would:
a Project row with ``scan_mode="url"`` and no uploaded artifacts, pointed at
the bundled vulnerable target by URL only, scanned through
``services.scan_service.execute_scan`` — the exact function a real scan
request invokes — and the persisted ``Scan``/``Endpoint``/``Finding`` rows are
inspected afterwards. The LLM layer is left disabled (no Ollama in test
environments); every other layer runs for real.

Requires a real database (JSONB/UUID columns are not portable to SQLite); set
``DATABASE_URL`` to a Postgres instance to run this file. It is skipped
automatically otherwise, so the rest of the suite stays fast and
dependency-free.
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
    pytest.skip(
        "requires a real Postgres DATABASE_URL (JSONB/UUID columns are not portable to SQLite)",
        allow_module_level=True,
    )

from app.db.base import Base  # noqa: E402
from app.db.models import Finding, Project, Scan, User  # noqa: E402
from app.security import hash_password  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def vulnapi_server(tmp_path_factory):
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    from app.config import settings

    previous_allowlist = settings.runtime_target_allowlist
    settings.runtime_target_allowlist = f"{previous_allowlist},127.0.0.1:{port}"

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
        settings.runtime_target_allowlist = previous_allowlist


@pytest.fixture()
def db_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(os.environ["DATABASE_URL"], future=True)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    session = SessionLocal()
    try:
        yield session, engine
    finally:
        session.close()


def test_execute_scan_url_mode_persists_endpoints_and_confirms_bola(vulnapi_server, db_session, monkeypatch):
    from contextlib import contextmanager

    import app.services.scan_service as scan_service

    session, engine = db_session

    @contextmanager
    def _fake_session_scope():
        from sqlalchemy.orm import sessionmaker

        SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
        s = SessionLocal()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    monkeypatch.setattr(scan_service, "session_scope", _fake_session_scope)

    user = User(email=f"url-mode-tester-{uuid.uuid4().hex[:8]}@apisentinel.local", password_hash=hash_password("x" * 12), role="analyst")
    session.add(user)
    session.flush()

    project = Project(
        owner_id=user.id,
        name="URL-mode integration test",
        scan_mode="url",
        runtime_base_url=vulnapi_server,
        target_authorized=True,
        authorization_method="manual",
        runtime_credentials={
            "login_path": "/login",
            "login_style": "json",
            "identifier_field": "email",
            "token_field": "access_token",
            "users": [
                {"label": "alice", "email": "alice@vulnshop.test", "password": "alice-password", "object_id": "1001"},
                {"label": "bob", "email": "bob@vulnshop.test", "password": "bob-password", "object_id": "1002"},
            ],
        },
    )
    session.add(project)
    session.flush()

    scan = Scan(
        project_id=project.id,
        status="queued",
        options={"run_static": True, "run_llm": False, "run_runtime": True},
    )
    session.add(scan)
    session.commit()
    scan_id = scan.id

    scan_service.execute_scan(scan_id)

    refreshed = session.get(Scan, scan_id)
    session.refresh(refreshed)
    assert refreshed.status == "completed", refreshed.error

    parser_status = (refreshed.layer_status or {}).get("parser", {})
    assert parser_status.get("source_mode") == "url"
    assert parser_status.get("status") == "ok"
    assert parser_status.get("openapi_found") is True
    assert (parser_status.get("endpoints") or 0) >= 15

    endpoints = session.get(Project, project.id).endpoints
    assert endpoints, "expected web-discovered endpoints to be persisted"
    assert all(e.discovered_via in {"web", "openapi"} for e in endpoints) or any(
        e.discovered_via == "web" for e in endpoints
    )

    findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
    bola = [
        f
        for f in findings
        if f.owasp_category == "API1" and f.path == "/orders/{order_id}" and not f.needs_manual_review
    ]
    assert bola, "expected a runtime-confirmed BOLA finding on GET /orders/{order_id}"
    assert bola[0].confidence >= 0.9

    assert (refreshed.stats or {}).get("runtime_confirmed", 0) >= 1


def test_execute_scan_url_mode_without_authorization_fails_closed(db_session, monkeypatch):
    """A url-mode project pointed at a non-allowlisted, non-authorized host must
    fail the scan outright, not silently complete with zero endpoints."""
    from contextlib import contextmanager

    import app.services.scan_service as scan_service

    session, engine = db_session

    @contextmanager
    def _fake_session_scope():
        from sqlalchemy.orm import sessionmaker

        SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
        s = SessionLocal()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    monkeypatch.setattr(scan_service, "session_scope", _fake_session_scope)

    user = User(email=f"unauth-tester-{uuid.uuid4().hex[:8]}@apisentinel.local", password_hash=hash_password("x" * 12), role="analyst")
    session.add(user)
    session.flush()

    project = Project(
        owner_id=user.id,
        name="Unauthorized URL-mode project",
        scan_mode="url",
        runtime_base_url="http://93.184.216.34",
        target_authorized=False,
    )
    session.add(project)
    session.flush()

    scan = Scan(project_id=project.id, status="queued", options={"run_static": True, "run_llm": False})
    session.add(scan)
    session.commit()
    scan_id = scan.id

    scan_service.execute_scan(scan_id)

    refreshed = session.get(Scan, scan_id)
    session.refresh(refreshed)
    assert refreshed.status == "failed"
    assert "authoriz" in (refreshed.error or "").lower() or "allowlist" in (refreshed.error or "").lower()
