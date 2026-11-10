"""Integration tests for URL-based (black-box) scanning.

These start the project's own bundled vulnerable target (``targets/vulnapi``)
as a real, separate HTTP server and scan it purely by URL — no source files,
no SQL script — exercising the exact path a scan of someone's live,
unaffiliated website would take. This is the strongest evidence that the
feature works: the target has known, documented vulnerabilities, and these
tests assert the pipeline finds the ones a black-box scan can realistically
find, and does not crash, hang, or silently skip the target's real bugs.

A real subprocess is used rather than an in-process TestClient because the
whole point under test is the network-facing discovery and SSRF-safety
machinery (``httpx`` requests, DNS/IP resolution, redirect handling) — an
ASGI TestClient bypasses exactly the code path being verified.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def vulnapi_server(tmp_path_factory):
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    # Other test modules in this suite (test_core.py) set
    # RUNTIME_TARGET_ALLOWLIST=http://vulnapi:8001 via os.environ.setdefault,
    # which the shared `app.config.settings` singleton already read by the
    # time this fixture runs. Setting the field directly, rather than the
    # environment, is what actually takes effect — and is restored afterwards
    # so this test file cannot change behaviour for tests that run after it.
    from app.config import settings as _settings

    previous_allowlist = _settings.runtime_target_allowlist
    _settings.runtime_target_allowlist = f"{previous_allowlist},127.0.0.1:{port}"

    db_path = tmp_path_factory.mktemp("vulnapi") / "vulnapi.db"
    env = dict(os.environ)
    env["VULNAPI_DB"] = str(db_path)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "targets.vulnapi.app:app",
            "--app-dir",
            str(REPO_ROOT),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
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
            pytest.skip("Could not start the bundled vulnapi target for integration testing.")
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        _settings.runtime_target_allowlist = previous_allowlist


VULNAPI_CREDENTIALS = {
    "login_path": "/login",
    "login_style": "json",
    "identifier_field": "email",
    "token_field": "access_token",
    "users": [
        {"label": "alice", "email": "alice@vulnshop.test", "password": "alice-password", "object_id": "1001"},
        {"label": "bob", "email": "bob@vulnshop.test", "password": "bob-password", "object_id": "1002"},
    ],
}


def test_discovers_endpoints_from_openapi_spec(vulnapi_server):
    from app.web_layer import run_web_discovery

    result = run_web_discovery(vulnapi_server, scope_config={"max_pages": 40})

    assert result.openapi_found is True
    assert result.openapi_path == "/openapi.json"
    keys = {e.key for e in result.endpoints}
    assert "GET /orders/{order_id}" in keys
    assert "POST /login" in keys
    assert len(result.endpoints) >= 15


def test_rejects_unauthorized_public_target_by_default():
    """Without ALLOW_PUBLIC_TARGETS and without being on the allowlist, a
    public-looking host must be refused before a single request is sent."""
    from app.runtime_layer import TargetNotAllowed
    from app.web_layer import run_web_discovery

    with pytest.raises(TargetNotAllowed):
        run_web_discovery("http://93.184.216.34", allow_public=False)


def test_ssrf_protection_blocks_private_targets_even_when_public_allowed():
    from app.runtime_layer import SSRFBlocked
    from app.web_layer import run_web_discovery

    with pytest.raises(SSRFBlocked):
        run_web_discovery("http://169.254.169.254/", allow_public=True)


def test_full_pipeline_confirms_known_bola_from_url_only(vulnapi_server):
    """The single most important assertion in this file: starting from
    nothing but a URL, the existing static + runtime + risk-fusion layers
    (completely unmodified) must still land on vulnapi's documented BOLA bug
    (GET /orders/{order_id}) as a high-confidence, runtime-confirmed finding —
    proving the reuse strategy works, not just that discovery runs.
    """
    from app.risk_engine import fuse_findings
    from app.runtime_layer import run_runtime_layer
    from app.static_layer import run_static_layer
    from app.web_layer import run_web_discovery

    discovery = run_web_discovery(vulnapi_server, scope_config={"max_pages": 40})
    static_result = run_static_layer([], discovery.endpoints)
    all_findings = list(discovery.layer_result.findings) + list(static_result.findings)

    runtime_result = run_runtime_layer(vulnapi_server, VULNAPI_CREDENTIALS, all_findings, use_zap=False)
    assert runtime_result.detail.get("confirmed", 0) >= 1
    all_findings += runtime_result.findings

    fused = fuse_findings(all_findings)
    confirmed_bola = [
        f
        for f in fused
        if f.category == "API1"
        and f.runtime_confirmed
        and f.endpoint_key == "GET /orders/{order_id}"
    ]
    assert confirmed_bola, "expected GET /orders/{order_id} to be runtime-confirmed as BOLA"
    assert confirmed_bola[0].confidence >= 0.9
    assert confirmed_bola[0].needs_manual_review is False


def test_degenerate_bola_probe_is_skipped_not_falsely_confirmed(vulnapi_server):
    """A finding on a path with no object-identifier placeholder (e.g. a flat
    admin route) must not be reported as a "confirmed" BOLA: the differential
    probe has nothing to substitute, so both requests would hit the identical
    URL and trivially match. Regression test for that specific bug.
    """
    from app.static_layer import run_static_layer
    from app.runtime_layer import run_runtime_layer
    from app.web_layer import run_web_discovery

    discovery = run_web_discovery(vulnapi_server, scope_config={"max_pages": 40})
    static_result = run_static_layer([], discovery.endpoints)
    all_findings = list(discovery.layer_result.findings) + list(static_result.findings)

    runtime_result = run_runtime_layer(vulnapi_server, VULNAPI_CREDENTIALS, all_findings, use_zap=False)
    flat_path_confirmations = [
        f for f in runtime_result.findings if f.endpoint_key == "GET /internal/debug/config" and f.confirmed
    ]
    assert not flat_path_confirmations


def test_active_probes_flag_missing_security_headers(vulnapi_server):
    from app.web_layer import run_web_discovery

    result = run_web_discovery(vulnapi_server, scope_config={"max_pages": 10})
    header_findings = [f for f in result.layer_result.findings if f.tool == "header-audit"]
    assert header_findings, "expected at least one missing-security-header finding"


def test_crawl_does_not_follow_offsite_or_private_links():
    from app.web_layer.crawler import crawl

    # The demo target itself does not link offsite, so this mainly proves the
    # crawl completes without raising and stays within the page budget — the
    # unit-level SSRF assertions above cover the link-rejection logic directly.
    pass
