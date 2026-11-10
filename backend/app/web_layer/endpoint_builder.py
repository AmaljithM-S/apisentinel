"""Turn what was *discovered* on the live target into the same
``ParsedEndpoint`` shape the source-mode parser produces.

This is the key reuse decision of URL-based scanning: every downstream layer
(structural analysis, the LLM reasoning pipeline, the runtime differential
tester, the risk engine) already operates on ``ParsedEndpoint`` and has no idea
whether ``source_code`` holds real Python or a description of observed HTTP
behaviour. By building the same object here, none of those layers need to
change at all.
"""

from __future__ import annotations

import json
from typing import Dict, List, Sequence

from app.parser.fastapi_parser import ParsedEndpoint
from app.parser.openapi_parser import spec_operations
from app.web_layer.crawler import CrawledEndpoint
from app.web_layer.js_crawler import RenderedPage

# A field/parameter name that strongly suggests an object identifier, used to
# recover ``path_params`` the way the source-mode AST parser would report
# them, which the differential BOLA probe substitutes values into.
_ID_HINTS = ("id", "uuid", "pk", "slug", "user_id", "account_id", "order_id")


def _path_params_from_path(path: str) -> List[str]:
    return [seg.strip("{}") for seg in path.split("/") if seg.startswith("{") and seg.endswith("}")]


def build_from_openapi(spec: Dict[str, object], base_url: str, spec_path: str) -> List[ParsedEndpoint]:
    """Build endpoints from a discovered OpenAPI/Swagger document.

    This is intentionally independent of ``app.parser.openapi_parser.enrich_with_openapi``
    (which only *annotates* endpoints already found in source): here the spec
    IS the primary source, since no source code was uploaded.
    """
    operations = spec_operations(spec)  # type: ignore[arg-type]
    out: List[ParsedEndpoint] = []
    for key, operation in operations.items():
        method, _, path = key.partition(" ")
        params = [
            str(p.get("name"))
            for p in (operation.get("parameters") or [])
            if isinstance(p, dict) and p.get("in") == "path" and p.get("name")
        ]
        if not params:
            params = _path_params_from_path(path)
        security = operation.get("security")
        global_security = spec.get("security") if isinstance(spec, dict) else None
        effective_security = security if security is not None else global_security
        auth_deps = ["openapi:declared-security-scheme"] if effective_security else []
        summary = str(operation.get("summary") or "").strip()
        description = str(operation.get("description") or "").strip()
        responses = operation.get("responses") or {}
        observed = (
            f"[Discovered via OpenAPI specification at {spec_path}]\n"
            f"{method.upper()} {path}\n"
            f"Summary: {summary or '(none declared)'}\n"
            f"Description: {description or '(none declared)'}\n"
            f"Declared security: {json.dumps(effective_security) if effective_security else '(none declared — endpoint may be unauthenticated)'}\n"
            f"Path parameters: {params or '(none)'}\n"
            f"Declared response codes: {sorted(responses.keys()) if isinstance(responses, dict) else '(unknown)'}\n"
        )
        out.append(
            ParsedEndpoint(
                method=method.upper(),
                path=path,
                handler_name=path.strip("/").replace("/", "_") or "root",
                source_file=f"{base_url}{spec_path}#{key}",
                source_code=observed,
                line_start=0,
                line_end=0,
                auth_dependencies=auth_deps,
                path_params=params,
                response_model=None,
                spec_summary=(summary or description)[:500] or None,
            )
        )
    return out


def build_from_crawl(endpoints: Sequence[CrawledEndpoint], base_url: str) -> List[ParsedEndpoint]:
    out: List[ParsedEndpoint] = []
    for item in endpoints:
        path_params = _path_params_from_path(item.path) or [
            p for p in item.params if any(hint in p.lower() for hint in _ID_HINTS)
        ]
        lines = [
            f"[Discovered by crawling {base_url} — no source code was available]",
            f"{item.method} {item.path}",
            f"Discovered via: {item.discovered_via}",
        ]
        if item.status is not None:
            lines.append(f"Observed HTTP status: {item.status}")
        if item.content_type:
            lines.append(f"Content-Type: {item.content_type}")
        if item.server_header:
            lines.append(f"Server header: {item.server_header}")
        if item.params:
            lines.append(f"Observed parameters/fields: {item.params}")
        if item.security_headers_present:
            lines.append(f"Security headers present: {item.security_headers_present}")
        if item.security_headers_missing:
            lines.append(f"Security headers missing: {item.security_headers_missing}")
        if item.body_excerpt:
            lines.append("Response excerpt (truncated):\n" + item.body_excerpt[:1200])
        out.append(
            ParsedEndpoint(
                method=item.method,
                path=item.path,
                handler_name=item.path.strip("/").replace("/", "_") or "root",
                source_file=f"{base_url}{item.path}",
                source_code="\n".join(lines),
                line_start=0,
                line_end=0,
                auth_dependencies=[],
                path_params=path_params,
                response_model=None,
                spec_summary=None,
            )
        )
    return out


def build_from_js_render(pages: Sequence[RenderedPage], base_url: str) -> List[ParsedEndpoint]:
    """Build endpoints from what a headless-browser render found that the
    static HTML never contained: post-render links, forms, and XHR/fetch
    calls the page made while settling. See ``js_crawler.py``."""
    out: List[ParsedEndpoint] = []
    seen_keys: set[str] = set()

    def _add(method: str, path: str, lines: List[str]) -> None:
        key = f"{method} {path}"
        if key in seen_keys:
            return
        seen_keys.add(key)
        out.append(
            ParsedEndpoint(
                method=method,
                path=path,
                handler_name=path.strip("/").replace("/", "_") or "root",
                source_file=f"{base_url}{path}",
                source_code="\n".join(lines),
                line_start=0,
                line_end=0,
                auth_dependencies=[],
                path_params=_path_params_from_path(path),
                response_model=None,
                spec_summary=None,
            )
        )

    for page in pages:
        for link in page.links:
            path = _relative_path(link, base_url)
            if path is None:
                continue
            _add(
                "GET",
                path,
                [
                    f"[Discovered by rendering {page.url} in a headless browser — link only exists after JavaScript runs]",
                    f"GET {path}",
                ],
            )
        for form in page.forms:
            action = form.get("action") or page.url
            path = _relative_path(action, base_url)
            if path is None:
                continue
            method = str(form.get("method") or "GET").upper()
            fields = [f for f in (form.get("fields") or []) if f]
            _add(
                method,
                path,
                [
                    f"[Discovered by rendering {page.url} in a headless browser — form only exists after JavaScript runs]",
                    f"{method} {path}",
                    f"Observed form fields: {fields}",
                ],
            )
        for xhr in page.xhr_requests:
            method, _, raw_path = xhr.partition(" ")
            path = raw_path if raw_path.startswith("/") else _relative_path(raw_path, base_url)
            if not path:
                continue
            _add(
                method or "GET",
                path,
                [
                    f"[Discovered by rendering {page.url} in a headless browser — XHR/fetch call made by client-side JavaScript]",
                    f"{method} {path}",
                ],
            )
    return out


def _relative_path(url: str, base_url: str) -> str | None:
    from urllib.parse import urlparse

    base_host = urlparse(base_url).hostname
    parsed = urlparse(url)
    if parsed.hostname and base_host and parsed.hostname != base_host:
        return None
    return parsed.path or "/"


def merge(*endpoint_lists: Sequence[ParsedEndpoint]) -> List[ParsedEndpoint]:
    """Merge endpoint lists in priority order: the first list to mention a
    given (method, path) key wins. Call with the most precise source first —
    typically OpenAPI, then plain-HTML crawl, then JS-rendered discovery."""
    by_key: Dict[str, ParsedEndpoint] = {}
    for endpoints in endpoint_lists:
        for endpoint in endpoints:
            by_key.setdefault(endpoint.key, endpoint)
    return list(by_key.values())
