"""Best-effort discovery of a machine-readable API spec on the live target.

When a running service happens to publish an OpenAPI/Swagger document, that is
by far the most precise source of endpoints, methods, parameters and security
schemes a black-box scan can get — far better than guessing from crawled HTML —
so it is always tried first. If nothing is found, the crawler (``crawler.py``)
is the fallback, and the two are additive: a spec found at a non-standard path
or behind an authenticated link discovered on the dashboard is still merged in.

Every GET here goes through the normal client, which is already pointed at an
authorized, allowlist-checked host by the caller, so no additional target
validation is done in this module.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import httpx

# Ordered by how common each layout is in real deployments; the loop stops at
# the first hit, so the more common paths come first for speed.
COMMON_SPEC_PATHS: Tuple[str, ...] = (
    "/openapi.json",
    "/api/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/api/swagger.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/api-docs",
    "/v3/api-docs.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/.well-known/openapi.json",
)


def _looks_like_spec(text: str) -> bool:
    head = text[:2000]
    return ('"openapi"' in head or '"swagger"' in head) and (
        '"paths"' in text[:20000] or "paths:" in text[:20000]
    )


def discover_openapi(
    base_url: str, client: httpx.Client
) -> Optional[Dict[str, str]]:
    """Return ``{"path": ..., "raw": ...}`` for the first spec found, else None."""
    for candidate in COMMON_SPEC_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", candidate.lstrip("/"))
        try:
            response = client.get(url)
        except httpx.HTTPError:
            continue
        if response.status_code != 200:
            continue
        content_type = response.headers.get("content-type", "")
        if "html" in content_type.lower():
            continue
        text = response.text
        if _looks_like_spec(text):
            return {"path": candidate, "raw": text}
    return None


def discover_graphql_introspection(base_url: str, client: httpx.Client) -> Optional[Dict[str, object]]:
    """A single, non-destructive GraphQL introspection probe.

    Only the standard ``__schema { queryType { name } }`` query is sent — just
    enough to confirm a GraphQL endpoint exists and is introspectable, which is
    itself a security-misconfiguration finding on a production system (API8:
    introspection should normally be disabled outside development). The full
    schema is not pulled, since nothing downstream in this project consumes a
    GraphQL schema yet; this keeps the probe cheap and clearly bounded.
    """
    for candidate in ("/graphql", "/api/graphql", "/graphql/console"):
        url = urljoin(base_url.rstrip("/") + "/", candidate.lstrip("/"))
        try:
            response = client.post(
                url,
                json={"query": "{ __schema { queryType { name } } }"},
                headers={"content-type": "application/json"},
            )
        except httpx.HTTPError:
            continue
        if response.status_code != 200:
            continue
        try:
            payload = response.json()
        except ValueError:
            continue
        if isinstance(payload, dict) and payload.get("data", {}).get("__schema"):
            return {"path": candidate, "introspection_enabled": True}
    return None
