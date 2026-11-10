"""A small, safe-by-default black-box crawler.

This is the discovery half of URL-based scanning: given only a base URL, find
the pages, forms and HTTP endpoints an unauthenticated (or, with credentials,
authenticated) visitor can reach, without any source code or SQL script being
uploaded. It plays the same role the parser (``app.parser``) plays in
source-mode: it turns the target into a list of ``ParsedEndpoint`` records that
every downstream layer already knows how to consume.

Design choices, and why:

* **Same-origin, allowlist-revalidated.** Every link, before it is queued, is
  checked again by ``assert_link_allowed`` — not just "is it HTML", but "is it
  still inside the one host we were authorized to test, and does it still
  resolve to a public address". See ``runtime_layer.safety`` for the model.
* **Redirects are not auto-followed.** ``httpx`` is configured with
  ``follow_redirects=False`` and each ``Location`` header is validated and
  queued like any other link. This is the OWASP SSRF Cheat Sheet's "re-validate
  on every redirect" control, applied literally.
* **Bounded.** A page count cap, a depth cap, and a small per-request delay
  keep the crawl inside the "request limits" the review explicitly asked for,
  and keep a slow or very large site from turning one scan into a denial of
  service against the thing being tested.
* **Read-only.** The crawler only ever issues GET requests. Forms are
  *recorded* (their action, method and field names) so later layers can reason
  about them, but a form is never submitted during discovery — submitting an
  unknown form is indistinguishable from fuzzing, which is a separate,
  explicitly opt-in capability (``active_probes`` for benign single-shot checks,
  ZAP Active Scan for a real attack sweep).
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

import httpx

from app.runtime_layer.safety import TargetNotAllowed, assert_link_allowed, assert_target_allowed

try:
    from bs4 import BeautifulSoup

    _HAVE_BS4 = True
except ImportError:  # pragma: no cover - bs4 is a declared dependency
    _HAVE_BS4 = False

_REDIRECT_CODES = {301, 302, 303, 307, 308}
_SENSITIVE_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
}


@dataclass
class CrawledForm:
    action: str
    method: str
    fields: List[str]


@dataclass
class CrawledEndpoint:
    """One observed (method, path) pair, with just enough live evidence for the
    later layers to reason about it without ever having seen source code."""

    method: str
    path: str
    status: Optional[int]
    content_type: str
    params: List[str] = field(default_factory=list)
    discovered_via: str = "crawl"
    security_headers_present: List[str] = field(default_factory=list)
    security_headers_missing: List[str] = field(default_factory=list)
    body_excerpt: str = ""
    server_header: Optional[str] = None


@dataclass
class CrawlResult:
    pages_visited: int = 0
    pages_skipped: int = 0
    endpoints: Dict[Tuple[str, str], CrawledEndpoint] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0


def _normalise(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    # Fragments are client-side only and query order is not meaningful for
    # deduplication purposes here; normalising both keeps the "seen" set small
    # without under-counting genuinely distinct endpoints.
    return urlunsplit((parts.scheme, parts.netloc.lower(), path, parts.query, ""))


def _path_params(path: str) -> List[str]:
    """Replace the trailing numeric/UUID-looking segment with a placeholder.

    A crawler never sees ``{id}`` in a URL the way source code would spell it;
    this heuristic recovers the same shape so the differential BOLA probe
    (which substitutes ``{...}``) and the risk engine's per-endpoint grouping
    both still work the way they do in source mode.
    """
    import re

    segments = [s for s in path.split("/") if s != ""]
    out = []
    params: List[str] = []
    for seg in segments:
        if re.fullmatch(r"\d+", seg) or re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", seg
        ):
            out.append("{id}")
            params.append("id")
        else:
            out.append(seg)
    return params


def _templated_path(path: str) -> str:
    import re

    segments = [s for s in path.split("/") if s != ""]
    out = []
    for seg in segments:
        if re.fullmatch(r"\d+", seg) or re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", seg
        ):
            out.append("{id}")
        else:
            out.append(seg)
    return "/" + "/".join(out)


def crawl(
    start_url: str,
    *,
    max_pages: int = 60,
    max_depth: int = 6,
    timeout_seconds: int = 10,
    request_delay_ms: int = 150,
    user_agent: str = "APISentinel-WebScanner/1.0",
    extra_headers: Optional[Dict[str, str]] = None,
    allow_public: Optional[bool] = None,
) -> CrawlResult:
    started = time.monotonic()
    result = CrawlResult()

    start_url = assert_target_allowed(start_url, allow_public=allow_public)
    primary_host = urlparse(start_url).hostname or ""

    headers = {"User-Agent": user_agent}
    if extra_headers:
        headers.update(extra_headers)

    seen: Set[str] = set()
    queue: deque[Tuple[str, int]] = deque([(start_url, 0)])

    with httpx.Client(timeout=timeout_seconds, follow_redirects=False, headers=headers) as client:
        while queue and len(result.endpoints) < max_pages * 4 and result.pages_visited < max_pages:
            url, depth = queue.popleft()
            norm = _normalise(url)
            if norm in seen:
                continue
            seen.add(norm)

            try:
                assert_link_allowed(url, primary_host, allow_public=allow_public)
            except TargetNotAllowed as exc:
                result.pages_skipped += 1
                result.warnings.append(str(exc))
                continue

            if request_delay_ms:
                time.sleep(request_delay_ms / 1000.0)

            try:
                response = client.get(url)
            except httpx.HTTPError as exc:
                result.warnings.append(f"GET {url} failed: {exc}")
                continue

            if response.status_code in _REDIRECT_CODES and depth < max_depth:
                location = response.headers.get("location")
                if location:
                    nxt = urljoin(url, location)
                    try:
                        assert_link_allowed(nxt, primary_host, allow_public=allow_public)
                        if _normalise(nxt) not in seen:
                            queue.append((nxt, depth + 1))
                    except TargetNotAllowed as exc:
                        result.warnings.append(f"redirect from {url}: {exc}")
                continue

            result.pages_visited += 1
            parsed = urlparse(url)
            path = parsed.path or "/"
            content_type = response.headers.get("content-type", "")
            key = ("GET", _templated_path(path))
            if key not in result.endpoints:
                present = [h for h in _SENSITIVE_HEADERS if h in {k.lower() for k in response.headers}]
                missing = [h for h in _SENSITIVE_HEADERS if h not in present]
                result.endpoints[key] = CrawledEndpoint(
                    method="GET",
                    path=key[1],
                    status=response.status_code,
                    content_type=content_type,
                    params=_path_params(path) + ([p for p in parsed.query.split("&") if p] and [
                        q.split("=")[0] for q in parsed.query.split("&") if q
                    ]),
                    discovered_via="crawl",
                    security_headers_present=present,
                    security_headers_missing=missing,
                    body_excerpt=response.text[:1200] if "text" in content_type or "json" in content_type else "",
                    server_header=response.headers.get("server"),
                )

            if depth >= max_depth or response.status_code >= 400:
                continue
            if not _HAVE_BS4 or "text/html" not in content_type:
                continue

            try:
                soup = BeautifulSoup(response.text[:2_000_000], "lxml")
            except Exception as exc:  # noqa: BLE001 - a malformed page must not kill the crawl
                result.warnings.append(f"could not parse HTML at {url}: {exc}")
                continue

            for anchor in soup.find_all("a", href=True):
                nxt = urljoin(url, anchor["href"])
                if urlparse(nxt).scheme not in {"http", "https"}:
                    continue
                if _normalise(nxt) not in seen:
                    queue.append((nxt, depth + 1))

            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                method = str(form.get("method") or "GET").upper()
                fields = [
                    str(tag.get("name"))
                    for tag in form.find_all(["input", "select", "textarea"])
                    if tag.get("name")
                ]
                form_path = _templated_path(urlparse(action).path or "/")
                fkey = (method, form_path)
                existing = result.endpoints.get(fkey)
                if existing is None:
                    result.endpoints[fkey] = CrawledEndpoint(
                        method=method,
                        path=form_path,
                        status=None,
                        content_type="",
                        params=fields,
                        discovered_via="form",
                    )
                elif fields:
                    existing.params = sorted(set(existing.params) | set(fields))
                try:
                    assert_link_allowed(action, primary_host, allow_public=allow_public)
                    if method == "GET" and _normalise(action) not in seen:
                        queue.append((action, depth + 1))
                except TargetNotAllowed:
                    pass

    result.duration_seconds = time.monotonic() - started
    return result
