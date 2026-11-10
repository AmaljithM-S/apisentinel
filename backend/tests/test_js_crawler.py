"""Tests for JavaScript-rendered-page discovery (web_layer/js_crawler.py).

Serves a tiny static page, in-process, whose links/forms/API calls exist only
after a script runs — proving the plain HTML crawler would see nothing useful
here, while the headless-browser pass finds all three. Skipped automatically
if Playwright/Chromium is not installed, so the rest of the suite is
unaffected on a machine that does not have it.
"""

from __future__ import annotations

import http.server
import os
import socketserver
import threading

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite://")

from app.web_layer.js_crawler import crawl_js, is_available  # noqa: E402

if not is_available():
    pytest.skip("Playwright/Chromium is not installed in this environment", allow_module_level=True)

_HTML = b"""<html><head><title>JS test page</title></head><body>
<div id="root">Loading...</div>
<script>
document.getElementById("root").innerHTML =
  "<a href=/js-only-page>JS link</a><form method=POST action=/js-submit><input name=q></form>";
fetch("/api/js-data");
</script>
</body></html>"""


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(_HTML)

    def log_message(self, *args):
        pass


@pytest.fixture()
def js_test_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture(autouse=True)
def _allow_public(monkeypatch):
    from app.config import settings

    previous = settings.allow_public_targets
    settings.allow_public_targets = True
    yield
    settings.allow_public_targets = previous


def test_finds_link_form_and_xhr_only_present_after_js_runs(js_test_server):
    result = crawl_js(js_test_server, max_pages=3, allow_public=True)

    assert not result.warnings
    assert len(result.pages) == 1
    page = result.pages[0]
    assert page.status == 200
    assert page.title == "JS test page"

    # None of these three appear anywhere in the raw HTML _HTML above — they
    # are only added by the <script> block, so finding them proves the
    # browser actually executed the page's JavaScript rather than just
    # fetching and returning the static markup.
    assert any(link.endswith("/js-only-page") for link in page.links)
    assert page.forms and page.forms[0]["action"].endswith("/js-submit")
    assert page.forms[0]["method"] == "POST"
    assert "q" in page.forms[0]["fields"]
    assert "GET /api/js-data" in page.xhr_requests


def test_respects_max_pages(js_test_server):
    result = crawl_js(
        js_test_server,
        seed_urls=[js_test_server + "/a", js_test_server + "/b", js_test_server + "/c"],
        max_pages=2,
        allow_public=True,
    )
    assert len(result.pages) <= 2


def test_graceful_when_playwright_unavailable(monkeypatch):
    import app.web_layer.js_crawler as js_crawler

    monkeypatch.setattr(js_crawler, "is_available", lambda: False)
    result = js_crawler.crawl_js("http://example.test", allow_public=True)
    assert result.pages == []
    assert any("not installed" in w for w in result.warnings)


def test_js_endpoints_merge_into_pipeline(js_test_server):
    """The full pipeline, with use_playwright on, must surface the
    JS-only link/form/XHR as real endpoints — not just as crawler-internal
    data nobody downstream ever sees."""
    from app.web_layer import run_web_discovery

    result = run_web_discovery(
        js_test_server,
        scope_config={"max_pages": 5, "use_playwright": True, "js_max_pages": 3},
        allow_public=True,
    )
    keys = {e.key for e in result.endpoints}
    assert "GET /js-only-page" in keys
    assert "POST /js-submit" in keys
    assert "GET /api/js-data" in keys
    assert result.layer_result.detail.get("js_rendering_used") is True
    assert result.layer_result.detail.get("js_pages_rendered", 0) >= 1
