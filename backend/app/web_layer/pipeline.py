"""Orchestrates URL-based (black-box) discovery for one project.

Order, and why:

1. **Authorize the target.** ``assert_target_allowed`` is the single gate
   (shared with the differential runtime tester) — nothing below this line
   runs unless the primary target is either operator-allowlisted or an
   explicitly authorized, public, non-private host.
2. **Discover a spec, if one exists.** Far more precise than guessing from
   HTML, so it is tried first and, where it overlaps with the crawl, wins.
3. **Crawl.** Finds pages, forms and endpoints a spec would not mention
   (legacy routes, a contact form, an admin page linked only from the footer).
4. **Merge** into one endpoint list, in the exact ``ParsedEndpoint`` shape the
   rest of the pipeline already understands.
5. **Run the conservative active probes** against that endpoint list (headers,
   sensitive paths, single-shot error/reflection checks) — safe by design, so
   these always run when web discovery runs.
6. **Optionally hand the target to ZAP** for spidering (more discovery) and,
   only when both the operator and this specific scan opted in, a real Active
   Scan.

The caller (``services.scan_service``) is responsible for feeding the returned
endpoints into the existing static/LLM/runtime/risk-engine stages unchanged —
this module's only job is turning "a URL" into the same currency the rest of
the framework already speaks.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.analysis_types import LayerFinding, LayerResult
from app.config import settings
from app.parser.fastapi_parser import ParsedEndpoint
from app.parser.openapi_parser import parse_openapi
from app.runtime_layer.safety import TargetNotAllowed, assert_target_allowed
from app.runtime_layer.zap_client import ZapClient
from app.web_layer.active_probes import run_active_probes
from app.web_layer.crawler import crawl
from app.web_layer.endpoint_builder import build_from_crawl, build_from_js_render, build_from_openapi, merge
from app.web_layer.js_crawler import crawl_js, is_available as js_rendering_available
from app.web_layer.openapi_discovery import discover_graphql_introspection, discover_openapi


@dataclass
class WebDiscoveryResult:
    endpoints: List[ParsedEndpoint] = field(default_factory=list)
    layer_result: LayerResult = field(default_factory=LayerResult)
    pages_visited: int = 0
    openapi_found: bool = False
    openapi_path: Optional[str] = None
    graphql_found: bool = False
    js_pages_rendered: int = 0
    js_rendering_used: bool = False


def run_web_discovery(
    target_url: str,
    *,
    scope_config: Optional[Dict[str, Any]] = None,
    allow_public: Optional[bool] = None,
) -> WebDiscoveryResult:
    started = time.monotonic()
    scope_config = scope_config or {}
    result = LayerResult()

    # Re-asserted here even though the API layer already checked it before
    # accepting the scan: this module must be safe to call from anywhere, and
    # a security control that only one caller remembers to apply is not a
    # control. See runtime_layer.safety module docstring.
    target_url = assert_target_allowed(target_url, allow_public=allow_public)

    max_pages = int(scope_config.get("max_pages") or settings.web_max_pages)
    max_pages = max(1, min(max_pages, settings.web_max_pages))

    discovery = WebDiscoveryResult()

    with httpx.Client(
        timeout=settings.web_request_timeout_seconds,
        follow_redirects=False,
        headers={"User-Agent": settings.web_user_agent},
    ) as probe_client:
        try:
            root_response = probe_client.get(target_url)
            root_headers = dict(root_response.headers)
        except httpx.HTTPError as exc:
            result.warnings.append(f"Could not reach {target_url} directly: {exc}")
            root_headers = {}

        spec = discover_openapi(target_url, probe_client)
        openapi_endpoints: List[ParsedEndpoint] = []
        if spec:
            try:
                parsed_spec = parse_openapi(spec["raw"])
                openapi_endpoints = build_from_openapi(parsed_spec, target_url, spec["path"])
                discovery.openapi_found = True
                discovery.openapi_path = spec["path"]
            except Exception as exc:  # noqa: BLE001 - a bad spec must not abort the scan
                result.warnings.append(f"Found a spec at {spec['path']} but could not parse it: {exc}")

        graphql = discover_graphql_introspection(target_url, probe_client)
        if graphql:
            discovery.graphql_found = True
            result.findings.append(
                LayerFinding(
                    source="web",
                    tool="graphql-introspection-probe",
                    category="API8",
                    title=f"GraphQL introspection is enabled at {graphql['path']}",
                    description=(
                        "The GraphQL endpoint answered a standard __schema introspection query. "
                        "Introspection exposes the entire API surface (types, fields, mutations) to "
                        "anyone who can reach the endpoint, which is normally disabled in production."
                    ),
                    severity="medium",
                    confidence=0.8,
                    remediation_hint="Disable introspection in production, or require authentication for it.",
                )
            )

    crawl_result = crawl(
        target_url,
        max_pages=max_pages,
        max_depth=min(settings.web_max_crawl_depth, int(scope_config.get("max_depth") or settings.web_max_crawl_depth)),
        timeout_seconds=settings.web_request_timeout_seconds,
        request_delay_ms=settings.web_request_delay_ms,
        user_agent=settings.web_user_agent,
        allow_public=allow_public,
    )
    crawl_endpoints = build_from_crawl(list(crawl_result.endpoints.values()), target_url)
    discovery.pages_visited = crawl_result.pages_visited
    result.warnings.extend(crawl_result.warnings[:25])
    if len(crawl_result.warnings) > 25:
        result.warnings.append(f"...and {len(crawl_result.warnings) - 25} more crawl warnings.")

    js_endpoints: List[ParsedEndpoint] = []
    if scope_config.get("use_playwright"):
        if js_rendering_available():
            # Hand the JS pass the pages the plain crawler already fetched the
            # HTML for (cheap to reuse as seeds) rather than re-discovering
            # the same ones; it renders at most this many of them with a real
            # browser, which is far slower per page than a plain GET.
            seed_urls = [
                target_url.rstrip("/") + e.path
                for e in crawl_endpoints[: settings.web_max_pages]
                if e.method == "GET"
            ]
            js_max_pages = min(
                int(scope_config.get("js_max_pages") or 15), settings.web_max_pages
            )
            js_result = crawl_js(
                target_url,
                seed_urls=seed_urls,
                max_pages=js_max_pages,
                page_timeout_ms=settings.web_request_timeout_seconds * 1000 * 2,
                allow_public=allow_public,
            )
            js_endpoints = build_from_js_render(js_result.pages, target_url)
            discovery.js_pages_rendered = len(js_result.pages)
            discovery.js_rendering_used = True
            result.warnings.extend(js_result.warnings[:15])
            if len(js_result.warnings) > 15:
                result.warnings.append(f"...and {len(js_result.warnings) - 15} more JS-rendering warnings.")
        else:
            result.warnings.append(
                "JavaScript-rendered-page crawling was requested but Playwright/Chromium is not "
                "installed in this deployment. See docs/WEB_SCANNING.md for how to enable it."
            )

    # Priority on overlap: a declared OpenAPI spec is most precise, then a
    # plain HTML crawl, then anything only visible after rendering JS.
    endpoints = merge(openapi_endpoints, crawl_endpoints, js_endpoints)
    include = scope_config.get("include_patterns") or []
    exclude = scope_config.get("exclude_patterns") or []
    if include:
        endpoints = [e for e in endpoints if any(p in e.path for p in include)]
    if exclude:
        endpoints = [e for e in endpoints if not any(p in e.path for p in exclude)]
    discovery.endpoints = endpoints

    if scope_config.get("run_active_probes", True):
        try:
            result.findings.extend(
                run_active_probes(
                    target_url,
                    endpoints,
                    root_headers,
                    timeout_seconds=settings.web_request_timeout_seconds,
                    user_agent=settings.web_user_agent,
                )
            )
        except Exception as exc:  # noqa: BLE001 - probes must degrade, not abort the scan
            result.warnings.append(f"Active probes raised an unexpected error and were stopped: {exc}")

    zap = ZapClient()
    if scope_config.get("use_zap_spider") and zap.configured and zap.available():
        spider_outcome = zap.spider(target_url, timeout_seconds=min(180, settings.web_request_timeout_seconds * 20))
        result.detail["zap_spider"] = spider_outcome
    elif scope_config.get("use_zap_spider"):
        result.warnings.append("ZAP spider was requested but ZAP is not configured or not reachable.")

    if scope_config.get("run_active_scan"):
        if not settings.zap_enable_active_scan:
            result.warnings.append(
                "This scan requested ZAP's Active Scan, but the operator has not enabled it "
                "(ZAP_ENABLE_ACTIVE_SCAN=false). No attack traffic was sent."
            )
        elif zap.configured and zap.available():
            active_findings = zap.active_scan(target_url)
            result.findings.extend(active_findings)
            result.detail["zap_active_scan_alerts"] = len(active_findings)
        else:
            result.warnings.append("Active Scan was requested but ZAP is not configured or not reachable.")

    result.duration_seconds = time.monotonic() - started
    result.detail.update(
        {
            "target_url": target_url,
            "pages_visited": discovery.pages_visited,
            "endpoints_discovered": len(endpoints),
            "openapi_found": discovery.openapi_found,
            "openapi_path": discovery.openapi_path,
            "graphql_found": discovery.graphql_found,
            "js_rendering_used": discovery.js_rendering_used,
            "js_pages_rendered": discovery.js_pages_rendered,
        }
    )
    discovery.layer_result = result
    return discovery
