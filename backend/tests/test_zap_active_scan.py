"""Tests for the ZAP spider and Active Scan integration
(runtime_layer/zap_client.py, wired into web_layer/pipeline.py).

No real ZAP instance is available in every environment this project is
developed in, so a tiny fake ZAP REST API is served in-process — real HTTP
calls over a real socket, exercising the actual request/parsing code in
``ZapClient``, just against a stand-in server instead of the real ZAP image
used in Docker Compose. This is the same trade-off, and the same reliable
in-process-server pattern, used for the other web_layer tests in this suite.
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import threading
from urllib.parse import urlparse

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite://")

from app.runtime_layer.zap_client import ZapClient  # noqa: E402


class _FakeZapHandler(http.server.BaseHTTPRequestHandler):
    alerts = [
        {"alert": "SQL Injection", "risk": "High", "confidence": "High",
         "url": "http://target.test/items?id=1", "description": "fake alert for testing",
         "solution": "use parameterised queries", "cweid": "89"},
    ]

    def _json(self, payload: dict, status: int = 200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/JSON/core/view/version/":
            self._json({"version": "fake-zap"})
        elif path == "/JSON/spider/action/scan/":
            self._json({"scan": "1"})
        elif path == "/JSON/spider/view/status/":
            self._json({"status": "100"})
        elif path == "/JSON/ascan/action/scan/":
            self._json({"scan": "1"})
        elif path == "/JSON/ascan/view/status/":
            self._json({"status": "100"})
        elif path == "/JSON/alert/view/alerts/":
            self._json({"alerts": self.alerts})
        else:
            self._json({}, status=404)

    def log_message(self, *args):
        pass


@pytest.fixture()
def fake_zap_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), _FakeZapHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture()
def zap_client(fake_zap_server, monkeypatch):
    from app.config import settings

    prev_url, prev_key = settings.zap_base_url, settings.zap_api_key
    settings.zap_base_url = fake_zap_server
    settings.zap_api_key = ""
    yield ZapClient()
    settings.zap_base_url, settings.zap_api_key = prev_url, prev_key


def test_available_against_fake_zap(zap_client):
    assert zap_client.configured is True
    assert zap_client.available() is True


def test_spider_reaches_completion(zap_client):
    result = zap_client.spider("http://target.test", timeout_seconds=10)
    assert result["ok"] is True
    assert result["progress"] == 100


def test_active_scan_disabled_by_operator_switch_returns_nothing(zap_client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "zap_enable_active_scan", False)
    findings = zap_client.active_scan("http://target.test")
    assert findings == []


def test_active_scan_enabled_returns_parsed_findings(zap_client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "zap_enable_active_scan", True)
    findings = zap_client.active_scan("http://target.test", timeout_seconds=10)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "API10"  # SQL Injection maps here via _ALERT_CATEGORY
    assert f.tool == "zap-active-scan"
    assert f.detail.get("scan_mode") == "active"
    assert f.confidence == 0.8  # alert confidence "High"


def test_pipeline_warns_when_active_scan_requested_but_operator_switch_off(fake_zap_server):
    """Two independent switches are required (operator + per-scan); this
    proves the operator switch alone being off blocks it, with a clear
    warning rather than silent failure — even though ZAP itself is reachable
    and would otherwise happily run the scan."""
    from app.config import settings
    from app.web_layer import run_web_discovery

    prev_url, prev_key, prev_switch = settings.zap_base_url, settings.zap_api_key, settings.zap_enable_active_scan
    settings.zap_base_url = fake_zap_server
    settings.zap_api_key = ""
    settings.zap_enable_active_scan = False
    try:
        result = run_web_discovery(
            "http://localhost:1",  # harmless: allowlisted by default, nothing need actually respond here
            scope_config={"max_pages": 1, "run_active_scan": True, "run_active_probes": False},
        )
    finally:
        settings.zap_base_url, settings.zap_api_key = prev_url, prev_key
        settings.zap_enable_active_scan = prev_switch

    assert any("ZAP_ENABLE_ACTIVE_SCAN" in w for w in result.layer_result.warnings)


def test_pipeline_runs_active_scan_when_both_switches_are_on(fake_zap_server):
    """The positive case, end to end through the real pipeline: operator
    switch on, per-scan opt-in on, ZAP reachable -> a real active-scan
    finding comes back through run_web_discovery's own findings list."""
    from app.config import settings
    from app.web_layer import run_web_discovery

    prev_url, prev_key, prev_switch = settings.zap_base_url, settings.zap_api_key, settings.zap_enable_active_scan
    settings.zap_base_url = fake_zap_server
    settings.zap_api_key = ""
    settings.zap_enable_active_scan = True
    try:
        result = run_web_discovery(
            "http://localhost:1",
            scope_config={"max_pages": 1, "run_active_scan": True, "run_active_probes": False},
        )
    finally:
        settings.zap_base_url, settings.zap_api_key = prev_url, prev_key
        settings.zap_enable_active_scan = prev_switch

    active_findings = [f for f in result.layer_result.findings if f.tool == "zap-active-scan"]
    assert len(active_findings) == 1
    assert active_findings[0].category == "API10"
    assert result.layer_result.detail.get("zap_active_scan_alerts") == 1


def test_active_scan_gracefully_returns_nothing_when_zap_unreachable():
    from app.config import settings

    prev_url = settings.zap_base_url
    settings.zap_base_url = "http://127.0.0.1:1"  # nothing listens here
    settings.zap_enable_active_scan = True
    try:
        client = ZapClient()
        assert client.available() is False
        assert client.active_scan("http://target.test", timeout_seconds=2) == []
    finally:
        settings.zap_base_url = prev_url
        settings.zap_enable_active_scan = False
