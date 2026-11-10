"""JavaScript-rendered-page discovery using a real, headless browser.

The plain crawler (``crawler.py``) only ever sees what a server returns on a
GET request — it never executes JavaScript. A single-page application that
builds its DOM, its links and its API calls client-side is largely invisible
to it: a page can look like one empty `<div id="root">` and nothing else.
Alsaidi, Alhuzali & Bamasag (2022) make exploring exactly this kind of
modern, JS-heavy application a central part of effective black-box discovery,
which is why this module exists rather than leaving the gap undocumented.

Design choices:

* **Optional and lazily imported.** Playwright and a real Chromium binary are
  a few hundred MB and meaningfully heavier to run than everything else in
  this project — not something to force into a default image on a
  resource-constrained deployment. This module is only imported, and
  Chromium only launched, when a caller explicitly asks for it
  (``scope_config.use_playwright=true``) and the package is actually
  installed; otherwise ``is_available()`` returns False and the rest of the
  pipeline proceeds exactly as it did before this module existed.
* **Same safety model, not a separate one.** Every URL the browser is sent to
  or that it discovers a link to still goes through
  ``runtime_layer.safety.assert_link_allowed`` before being visited or
  queued — rendering a page with a real browser does not relax the
  authorization/SSRF checks every other request in this project goes
  through.
* **Bounded and read-only.** A hard cap on how many pages get a real browser
  render (rendering is slow and resource-heavy compared to a plain GET), a
  per-page timeout, and no interaction with the page beyond letting it finish
  its initial render and settle — no clicking, no typing, no submitting.
  That boundary matches the rest of this project's black-box discovery (see
  ``crawler.py``'s own docstring): finding what exists, not acting on it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse

from app.runtime_layer.safety import TargetNotAllowed, assert_link_allowed

try:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    _HAVE_PLAYWRIGHT = True
except ImportError:  # pragma: no cover - exercised by is_available() instead
    _HAVE_PLAYWRIGHT = False


def is_available() -> bool:
    """Whether Playwright is importable *and* a Chromium build is actually
    installed. Both can be true/false independently — the package can be
    `pip install`-ed without ever running `playwright install chromium`."""
    if not _HAVE_PLAYWRIGHT:
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            browser.close()
        return True
    except Exception:  # noqa: BLE001 - any failure here just means "not available"
        return False


@dataclass
class RenderedPage:
    url: str
    status: Optional[int]
    title: str
    links: List[str] = field(default_factory=list)
    forms: List[dict] = field(default_factory=list)
    xhr_requests: List[str] = field(default_factory=list)  # "METHOD path"
    render_error: Optional[str] = None


@dataclass
class JsCrawlResult:
    pages: List[RenderedPage] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0


def crawl_js(
    start_url: str,
    *,
    seed_urls: Optional[List[str]] = None,
    max_pages: int = 15,
    page_timeout_ms: int = 12000,
    primary_host: Optional[str] = None,
    allow_public: Optional[bool] = None,
) -> JsCrawlResult:
    """Render up to ``max_pages`` pages in a real headless browser.

    ``seed_urls`` lets the caller hand in pages the plain-HTML crawler already
    found (so a JS pass is spent rendering real pages rather than
    rediscovering the same ones); ``start_url`` is always included. Links
    found *after* rendering, and any XHR/fetch calls the page makes while
    settling, are recorded for the caller to merge back into the main
    endpoint list the same way the plain crawler's output is.
    """
    result = JsCrawlResult()
    if not is_available():
        result.warnings.append(
            "Playwright/Chromium is not installed, so JavaScript-rendered pages were not crawled. "
            "See docs/WEB_SCANNING.md for how to enable it."
        )
        return result

    started = time.monotonic()
    host = primary_host or (urlparse(start_url).hostname or "")
    queue: List[str] = [start_url] + [u for u in (seed_urls or []) if u != start_url]
    seen: Set[str] = set()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--disable-gpu", "--no-sandbox"])
            context = browser.new_context(
                user_agent="APISentinel-WebScanner/1.0 (+authorized-security-assessment; JS-render)",
                ignore_https_errors=False,
            )
            context.set_default_timeout(page_timeout_ms)

            for url in queue:
                if len(result.pages) >= max_pages:
                    break
                if url in seen:
                    continue
                seen.add(url)
                try:
                    assert_link_allowed(url, host, allow_public=allow_public)
                except TargetNotAllowed as exc:
                    result.warnings.append(str(exc))
                    continue

                page = context.new_page()
                xhr: List[str] = []
                page.on(
                    "request",
                    lambda req, xhr=xhr: xhr.append(f"{req.method} {urlparse(req.url).path}")
                    if req.resource_type in ("xhr", "fetch")
                    else None,
                )
                rendered = RenderedPage(url=url, status=None, title="")
                try:
                    response = page.goto(url, wait_until="networkidle")
                    rendered.status = response.status if response else None
                    rendered.title = page.title()
                    anchors = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                    rendered.links = [a for a in anchors if urlparse(a).scheme in ("http", "https")]
                    forms = page.eval_on_selector_all(
                        "form",
                        "els => els.map(f => ({action: f.action, method: (f.method||'GET').toUpperCase(),"
                        " fields: Array.from(f.elements).map(e => e.name).filter(Boolean)}))",
                    )
                    rendered.forms = forms or []
                except PlaywrightError as exc:
                    rendered.render_error = str(exc)
                    result.warnings.append(f"Could not render {url}: {exc}")
                finally:
                    rendered.xhr_requests = sorted(set(xhr))
                    page.close()
                result.pages.append(rendered)
            context.close()
            browser.close()
    except Exception as exc:  # noqa: BLE001 - a browser crash must not abort the whole scan
        result.warnings.append(f"JS rendering stopped early: {exc}")

    result.duration_seconds = time.monotonic() - started
    return result
