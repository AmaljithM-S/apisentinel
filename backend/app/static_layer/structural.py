"""Deterministic structural analysis of parsed endpoints.

Bandit and Semgrep answer "is there dangerous syntax here?". They cannot answer
"is an ownership check *missing*?", because absence has no pattern to match.
This module closes that gap deterministically: it reasons over the endpoint's
AST — which parameters exist, which dependencies are injected, whether the
authenticated principal is ever compared against the requested object — and
emits low-to-moderate confidence findings that the LLM and runtime layers then
corroborate or refute.

It is deliberately conservative and fully reproducible (no model involved), so
it can run on every commit while the heavier layers run on a schedule.
"""

from __future__ import annotations

import re
import time
from typing import Iterable, List, Sequence

from app.analysis_types import LayerFinding, LayerResult
from app.parser.fastapi_parser import ParsedEndpoint

OWNER_COMPARISON = re.compile(
    r"(current_user|user|principal|caller|claims|token)[\w\.\[\]\"']*\s*(==|!=|\bis\b|\bin\b)"
    r"|(owner|user_id|account_id|customer_id)[\w\.\[\]\"']*\s*(==|!=)"
    r"|\.filter\([^)]*(owner|user_id|account_id)"
    r"|(owner_id|user_id)\s*=\s*(current_user|user|principal)",
    re.IGNORECASE,
)

ROLE_CHECK = re.compile(
    r"(role|is_admin|is_staff|scopes?|permissions?|has_role|require_role|require_admin)",
    re.IGNORECASE,
)

SENSITIVE_FIELDS = (
    "password",
    "password_hash",
    "hashed_password",
    "ssn",
    "social_security",
    "national_id",
    "aadhaar",
    "credit_card",
    "card_number",
    "cvv",
    "secret",
    "api_key",
    "token",
    "salt",
    "mfa_secret",
)

RETURNS_WHOLE_ROW = re.compile(
    r"return\s+(row|record|obj|item|result|user|account|entity)\b(?!\s*\.)"
    r"|return\s+dict\(\s*(row|record|user)\b"
    r"|return\s+\{\*\*",
    re.IGNORECASE,
)

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ADMIN_PATH = re.compile(r"/(admin|internal|manage|management|ops|debug)(/|$)", re.IGNORECASE)
PAGINATION = re.compile(r"\b(limit|page_size|per_page|offset|cursor|paginate)\b", re.IGNORECASE)
RATE_LIMIT = re.compile(r"(rate_?limit|throttl|slowapi|limiter)", re.IGNORECASE)
DEBUG_ENDPOINT = re.compile(r"/(debug|test|__|internal)/", re.IGNORECASE)


def _has_auth(endpoint: ParsedEndpoint) -> bool:
    joined = " ".join(endpoint.auth_dependencies).lower()
    if not joined:
        return False
    hints = ("current_user", "user", "auth", "token", "jwt", "oauth", "bearer", "apikey", "require")
    return any(hint in joined for hint in hints)


def _object_params(endpoint: ParsedEndpoint) -> List[str]:
    return [
        param
        for param in endpoint.path_params
        if re.search(r"(^|_)(id|uuid|pk|slug|number|no)$", param, re.IGNORECASE)
        or param.lower() in {"id", "uid", "userid", "user_id", "account_id", "order_id"}
    ]


def analyse_endpoints(endpoints: Sequence[ParsedEndpoint]) -> LayerResult:
    started = time.monotonic()
    findings: List[LayerFinding] = []

    for endpoint in endpoints:
        code = endpoint.source_code
        has_auth = _has_auth(endpoint)
        object_params = _object_params(endpoint)

        # --- API2: no authentication on a non-public operation ---------------
        if not has_auth and (endpoint.method in WRITE_METHODS or object_params):
            findings.append(
                LayerFinding(
                    source="static",
                    tool="structural",
                    category="API2",
                    title=f"No authentication dependency on {endpoint.key}",
                    description=(
                        "The handler declares no authentication dependency, yet it "
                        f"{'modifies state' if endpoint.method in WRITE_METHODS else 'accepts an object identifier'}. "
                        "Any unauthenticated caller can invoke it."
                    ),
                    severity="critical" if endpoint.method in WRITE_METHODS else "high",
                    confidence=0.6,
                    endpoint_key=endpoint.key,
                    source_file=endpoint.source_file,
                    line_start=endpoint.line_start,
                    stride=["Spoofing", "Elevation of Privilege"],
                    detail={"auth_dependencies": endpoint.auth_dependencies},
                    remediation_hint=(
                        "Inject an authentication dependency, e.g. "
                        "`user: User = Depends(get_current_user)`."
                    ),
                )
            )

        # --- API1: identifier accepted but never checked against the caller --
        if object_params and not OWNER_COMPARISON.search(code):
            findings.append(
                LayerFinding(
                    source="static",
                    tool="structural",
                    category="API1",
                    title=f"Object identifier is not authorised against the caller on {endpoint.key}",
                    description=(
                        f"The endpoint takes path parameter(s) {', '.join(object_params)} and "
                        "loads the referenced object, but the handler body never compares the "
                        "authenticated principal with the object's owner. Changing the "
                        "identifier is likely to return another user's data."
                    ),
                    severity="high",
                    confidence=0.55 if has_auth else 0.62,
                    endpoint_key=endpoint.key,
                    source_file=endpoint.source_file,
                    line_start=endpoint.line_start,
                    stride=["Elevation of Privilege", "Information Disclosure"],
                    detail={"path_params": object_params, "authenticated": has_auth},
                    remediation_hint=(
                        "Load the object, then reject the request unless it belongs to the "
                        "caller: `if obj.owner_id != current_user.id: raise HTTPException(403)`."
                    ),
                )
            )

        # --- API5: privileged surface without a role check -------------------
        if ADMIN_PATH.search(endpoint.path) and not ROLE_CHECK.search(
            code + " ".join(endpoint.auth_dependencies)
        ):
            findings.append(
                LayerFinding(
                    source="static",
                    tool="structural",
                    category="API5",
                    title=f"Administrative endpoint without a role check: {endpoint.key}",
                    description=(
                        "The route is under an administrative path prefix but neither the "
                        "dependencies nor the handler body verify a role, scope or permission."
                    ),
                    severity="high",
                    confidence=0.6,
                    endpoint_key=endpoint.key,
                    source_file=endpoint.source_file,
                    line_start=endpoint.line_start,
                    stride=["Elevation of Privilege"],
                    remediation_hint=(
                        "Guard the route with a role dependency, e.g. "
                        "`Depends(require_role('admin'))`."
                    ),
                )
            )

        # --- API3: response shape not constrained ----------------------------
        mentions_sensitive = [f for f in SENSITIVE_FIELDS if f in code.lower()]
        if endpoint.response_model is None and (
            mentions_sensitive or RETURNS_WHOLE_ROW.search(code)
        ):
            findings.append(
                LayerFinding(
                    source="static",
                    tool="structural",
                    category="API3",
                    title=f"Unconstrained response shape on {endpoint.key}",
                    description=(
                        "No `response_model` is declared and the handler returns a whole "
                        "record"
                        + (
                            f", while the surrounding code references sensitive field(s): "
                            f"{', '.join(sorted(set(mentions_sensitive))[:6])}."
                            if mentions_sensitive
                            else "."
                        )
                        + " Fields the client is not entitled to may be serialised into the response."
                    ),
                    severity="high" if mentions_sensitive else "medium",
                    confidence=0.6 if mentions_sensitive else 0.5,
                    endpoint_key=endpoint.key,
                    source_file=endpoint.source_file,
                    line_start=endpoint.line_start,
                    stride=["Information Disclosure"],
                    detail={"sensitive_terms": sorted(set(mentions_sensitive))},
                    remediation_hint=(
                        "Declare an explicit `response_model` listing only the fields the "
                        "client may see."
                    ),
                )
            )

        # --- API4: unbounded collection read ---------------------------------
        if (
            endpoint.method == "GET"
            and not endpoint.path_params
            and not PAGINATION.search(code)
            and not RATE_LIMIT.search(code)
            and re.search(r"\.all\(\)|SELECT \*|find\(\)", code, re.IGNORECASE)
        ):
            findings.append(
                LayerFinding(
                    source="static",
                    tool="structural",
                    category="API4",
                    title=f"Unbounded collection read on {endpoint.key}",
                    description=(
                        "The endpoint returns an entire collection with no pagination bound "
                        "and no rate limit, so a single request can exhaust memory or "
                        "database time."
                    ),
                    severity="medium",
                    confidence=0.5,
                    endpoint_key=endpoint.key,
                    source_file=endpoint.source_file,
                    line_start=endpoint.line_start,
                    stride=["Denial of Service"],
                    remediation_hint="Add required `limit`/`offset` bounds and a server-side maximum.",
                )
            )

        # --- API9: debug/internal surface left exposed ------------------------
        if DEBUG_ENDPOINT.search(endpoint.path + "/"):
            findings.append(
                LayerFinding(
                    source="static",
                    tool="structural",
                    category="API9",
                    title=f"Debug or internal endpoint exposed: {endpoint.key}",
                    description=(
                        "The route path indicates a debug or internal-only surface that is "
                        "registered on the public application."
                    ),
                    severity="medium",
                    confidence=0.55,
                    endpoint_key=endpoint.key,
                    source_file=endpoint.source_file,
                    line_start=endpoint.line_start,
                    stride=["Information Disclosure"],
                    remediation_hint="Remove the route or register it only in non-production builds.",
                )
            )

    result = LayerResult(findings=findings)
    result.duration_seconds = time.monotonic() - started
    return result


def merge_results(results: Iterable[LayerResult]) -> LayerResult:
    merged = LayerResult()
    for item in results:
        merged.findings.extend(item.findings)
        merged.warnings.extend(item.warnings)
        merged.duration_seconds += item.duration_seconds
        merged.ok = merged.ok and item.ok
        merged.detail.update(item.detail)
    return merged
