"""Lightweight, non-destructive checks that need a live target but are not a
full attack sweep.

Althunayyan et al. (2022) found that automated black-box scanners miss a
meaningful share of injection flaws and, just as importantly, that scanners
which fire large payload libraries generate many findings a reviewer cannot
trust without re-testing. The checks here deliberately sit on the conservative
end of that trade-off: each one issues at most a handful of extra read-only
requests, uses a single, well-known, non-destructive payload per check (never
a payload library), and is capped in confidence well below "confirmed" — each
finding is explicitly corroborating evidence for a human or for the runtime
differential layer, not a verdict on its own. A real attack-payload sweep is
OWASP ZAP's Active Scan (``runtime_layer.zap_client.active_scan``), which is
opt-in and clearly separated from these checks for exactly that reason.

Every finding uses ``source="web"``; the risk engine (``risk_engine.fusion``)
already treats an unrecognised source with a neutral weight of 1.0 and groups
by (category, endpoint) regardless of source, so no change was needed there to
support this new signal — it is fused and capped exactly like a static or
runtime finding would be.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Dict, List, Sequence
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

import httpx

from app.analysis_types import LayerFinding
from app.parser.fastapi_parser import ParsedEndpoint

# A short, curated list. Kept deliberately small: this is a courtesy inventory
# check, not a wordlist-driven brute force, so it stays within "request
# limits" and cannot itself be mistaken for an attack.
_SENSITIVE_PATHS: Sequence[tuple[str, str, re.Pattern]] = (
    ("/.env", "API3", re.compile(r"(^|\n)[A-Z_]+=.+")),
    ("/.git/config", "API9", re.compile(r"\[core\]")),
    ("/.git/HEAD", "API9", re.compile(r"^ref:")),
    ("/.well-known/apisentinel-authorization.txt", "API9", re.compile(r".")),  # our own marker, informational
    ("/actuator/env", "API3", re.compile(r'"propertySources"')),
    ("/actuator/health", "API9", re.compile(r'"status"')),
    ("/server-status", "API9", re.compile(r"Apache Server Status")),
    ("/wp-config.php.bak", "API3", re.compile(r"DB_PASSWORD")),
    ("/config.php.bak", "API3", re.compile(r"\$db|\$config", re.I)),
    ("/debug", "API9", re.compile(r"debug", re.I)),
    ("/.well-known/security.txt", "API9", re.compile(r"Contact:")),
)

_ERROR_SIGNATURES = (
    ("Traceback (most recent call last)", "Python/Django/Flask stack trace"),
    ("django.core", "Django internals exposed"),
    ("at System.", ".NET stack trace"),
    ("Microsoft.AspNetCore", "ASP.NET internals exposed"),
    ("java.lang.", "Java stack trace"),
    ("org.springframework", "Spring internals exposed"),
    ("Whitelabel Error Page", "Spring Boot default error page"),
    ("ORA-", "Oracle database error"),
    ("SQLSTATE", "SQL error (SQLSTATE)"),
    ("You have an error in your SQL syntax", "MySQL syntax error"),
    ("psycopg2.errors", "PostgreSQL driver error"),
    ("sqlite3.OperationalError", "SQLite driver error"),
    ("unterminated quoted string", "SQL syntax error"),
)

_MISSING_HEADER_HINT = {
    "strict-transport-security": (
        "HSTS is missing, so a user who types the plain-http address is not redirected to "
        "https automatically by the browser."
    ),
    "content-security-policy": "No Content-Security-Policy header was sent.",
    "x-content-type-options": "X-Content-Type-Options: nosniff is missing.",
    "x-frame-options": "No clickjacking protection header (X-Frame-Options / frame-ancestors) was sent.",
}


def check_security_headers(base_url: str, response_headers: Dict[str, str], https: bool) -> List[LayerFinding]:
    findings: List[LayerFinding] = []
    lowered = {k.lower(): v for k, v in response_headers.items()}
    missing = []
    for header, hint in _MISSING_HEADER_HINT.items():
        if header == "strict-transport-security" and not https:
            continue
        if header not in lowered:
            missing.append((header, hint))
    if missing:
        findings.append(
            LayerFinding(
                source="web",
                tool="header-audit",
                category="API8",
                title=f"Missing security headers on {base_url}",
                description=(
                    "The following protective response headers were not present: "
                    + "; ".join(hint for _h, hint in missing)
                ),
                severity="low",
                confidence=0.55,
                detail={"missing_headers": [h for h, _ in missing]},
                remediation_hint=(
                    "Set Strict-Transport-Security, Content-Security-Policy, "
                    "X-Content-Type-Options: nosniff and a frame-ancestors/X-Frame-Options policy "
                    "on every response, typically from a single middleware."
                ),
            )
        )

    origin = lowered.get("access-control-allow-origin")
    creds = lowered.get("access-control-allow-credentials", "").lower() == "true"
    if origin == "*" and creds:
        findings.append(
            LayerFinding(
                source="web",
                tool="header-audit",
                category="API8",
                title=f"Permissive CORS with credentials on {base_url}",
                description=(
                    "Access-Control-Allow-Origin: * is combined with "
                    "Access-Control-Allow-Credentials: true. Browsers forbid this combination "
                    "for credentialed requests, but some HTTP clients (and misconfigured proxies) "
                    "do not enforce it, so any site can attempt a credentialed cross-origin request."
                ),
                severity="high",
                confidence=0.75,
                remediation_hint="Echo back a specific, validated Origin instead of '*' when credentials are allowed.",
            )
        )
    server = lowered.get("server", "")
    if re.search(r"/\d", server):
        findings.append(
            LayerFinding(
                source="web",
                tool="header-audit",
                category="API8",
                title=f"Server header discloses version: {server}",
                description=(
                    f"The Server header ('{server}') includes a version number, which helps an "
                    "attacker match the target against known vulnerabilities for that exact build."
                ),
                severity="low",
                confidence=0.5,
                remediation_hint="Suppress or generalise the Server header at the reverse proxy.",
            )
        )
    return findings


def check_sensitive_paths(base_url: str, client: httpx.Client) -> List[LayerFinding]:
    findings: List[LayerFinding] = []
    for path, category, pattern in _SENSITIVE_PATHS:
        if path.endswith("apisentinel-authorization.txt"):
            continue  # that one is our own verification marker, never a finding
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            response = client.get(url)
        except httpx.HTTPError:
            continue
        if response.status_code != 200:
            continue
        body = response.text[:4000]
        if not pattern.search(body):
            continue
        findings.append(
            LayerFinding(
                source="web",
                tool="info-disclosure-probe",
                category=category,
                title=f"Sensitive path exposed: {path}",
                description=(
                    f"GET {path} returned 200 with content matching what a real "
                    f"{'configuration file' if category == 'API3' else 'internal/undocumented resource'} "
                    "would contain. The excerpt was not stored verbatim to avoid persisting secrets; "
                    "verify and remove or restrict access to this path."
                ),
                severity="high" if category == "API3" else "medium",
                confidence=0.6,
                detail={"path": path, "status": response.status_code},
                remediation_hint=f"Remove '{path}' from the deployed artifact or block it at the reverse proxy.",
            )
        )
    return findings


def check_error_disclosure(
    endpoints: Sequence[ParsedEndpoint], base_url: str, client: httpx.Client, *, max_probes: int = 8
) -> List[LayerFinding]:
    """Append a single apostrophe to one existing query/path value and look for
    a stack-trace or database-error signature in the response.

    This is the standard, well-documented "error-based" black-box injection
    check (see Althunayyan et al., 2022, and the OWASP Web Security Testing
    Guide's injection chapter): a single benign character that breaks naive
    string-built SQL, with no attempt to extract data, run a second query, or
    time the response. Only GET endpoints are probed, and only the first
    ``max_probes`` of them, to bound request volume.
    """
    findings: List[LayerFinding] = []
    probed = 0
    for endpoint in endpoints:
        if probed >= max_probes or endpoint.method != "GET":
            continue
        if "{id}" in endpoint.path:
            target_path = endpoint.path.replace("{id}", "1'")
        elif endpoint.path_params:
            continue
        else:
            parsed = urlparse(urljoin(base_url, endpoint.path))
            query = urlencode({"apisentinel_probe": "1'"})
            target_path = urlunparse(parsed._replace(query=query)).replace(base_url.rstrip("/"), "")
        url = urljoin(base_url.rstrip("/") + "/", target_path.lstrip("/"))
        try:
            response = client.get(url)
        except httpx.HTTPError:
            continue
        probed += 1
        body = response.text[:8000]
        for needle, label in _ERROR_SIGNATURES:
            if needle in body:
                findings.append(
                    LayerFinding(
                        source="web",
                        tool="error-signature-probe",
                        category="API10",
                        title=f"Possible injection flaw on {endpoint.key} ({label})",
                        description=(
                            f"Appending a single apostrophe to a parameter of {endpoint.key} produced a "
                            f"response containing a {label.lower()} signature ('{needle}'). This is a "
                            "corroborating, best-effort signal from a single benign probe, not proof of "
                            "exploitability — confirm with a focused manual test or OWASP ZAP's Active Scan "
                            "before treating it as confirmed."
                        ),
                        severity="high",
                        confidence=0.5,
                        endpoint_key=endpoint.key,
                        detail={"probe_url": url, "signature": needle},
                        remediation_hint="Use parameterised queries / an ORM; never concatenate request input into a query string.",
                    )
                )
                break
    return findings


def check_reflected_input(
    endpoints: Sequence[ParsedEndpoint], base_url: str, client: httpx.Client, *, max_probes: int = 8
) -> List[LayerFinding]:
    """Send a unique, inert marker as a parameter value and check whether it
    comes back unescaped in an HTML response.

    This never sends script tags or executes anything; it only measures
    whether user input is reflected without HTML-entity encoding, which is the
    precondition for reflected XSS, not proof of it. Confidence is capped low
    for the same reason noted in the module docstring.
    """
    findings: List[LayerFinding] = []
    probed = 0
    for endpoint in endpoints:
        if probed >= max_probes or endpoint.method != "GET" or not endpoint.path_params:
            continue
        marker = "apisentinel" + uuid.uuid4().hex[:8]
        target_path = endpoint.path
        for param in endpoint.path_params:
            target_path = target_path.replace("{" + param + "}", marker)
        if "{" in target_path:
            continue
        url = urljoin(base_url.rstrip("/") + "/", target_path.lstrip("/"))
        try:
            response = client.get(url)
        except httpx.HTTPError:
            continue
        probed += 1
        content_type = response.headers.get("content-type", "")
        if "html" not in content_type:
            continue
        if marker in response.text:
            findings.append(
                LayerFinding(
                    source="web",
                    tool="reflected-input-probe",
                    category="API10",
                    title=f"Unescaped input reflection on {endpoint.key}",
                    description=(
                        f"A unique marker value sent as a path parameter on {endpoint.key} was reflected "
                        "unescaped in an HTML response. This is the precondition for reflected XSS, not "
                        "proof of it — no script was executed. Treat as a lead for manual verification."
                    ),
                    severity="medium",
                    confidence=0.45,
                    endpoint_key=endpoint.key,
                    detail={"probe_url": url},
                    remediation_hint="HTML-encode all user-controlled output; prefer a templating engine with autoescaping on.",
                )
            )
    return findings


def run_active_probes(
    base_url: str,
    endpoints: Sequence[ParsedEndpoint],
    root_headers: Dict[str, str],
    *,
    timeout_seconds: int = 10,
    user_agent: str = "APISentinel-WebScanner/1.0",
) -> List[LayerFinding]:
    findings: List[LayerFinding] = []
    findings.extend(
        check_security_headers(base_url, root_headers, urlparse(base_url).scheme == "https")
    )
    with httpx.Client(
        timeout=timeout_seconds, follow_redirects=False, headers={"User-Agent": user_agent}
    ) as client:
        findings.extend(check_sensitive_paths(base_url, client))
        findings.extend(check_error_disclosure(endpoints, base_url, client))
        findings.extend(check_reflected_input(endpoints, base_url, client))
    return findings
