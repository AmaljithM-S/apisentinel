"""OWASP API Security Top 10 (2023) taxonomy with CWE and STRIDE mappings.

Single source of truth for category metadata. Classification code maps to a
category id here rather than duplicating titles and CWE ids across layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class Category:
    id: str
    title: str
    cwe: str
    stride: List[str] = field(default_factory=list)
    base_severity: str = "medium"
    description: str = ""


CATEGORIES: Dict[str, Category] = {
    "API1": Category(
        "API1",
        "Broken Object Level Authorization",
        "CWE-639",
        ["Elevation of Privilege", "Information Disclosure"],
        "high",
        "The endpoint accepts an object identifier without verifying that the "
        "authenticated caller owns or may access that object.",
    ),
    "API2": Category(
        "API2",
        "Broken Authentication",
        "CWE-287",
        ["Spoofing", "Elevation of Privilege"],
        "critical",
        "Authentication is missing, incorrectly verified, or bypassable.",
    ),
    "API3": Category(
        "API3",
        "Broken Object Property Level Authorization / Excessive Data Exposure",
        "CWE-213",
        ["Information Disclosure"],
        "high",
        "The response exposes more object properties than the client is "
        "entitled to receive, or accepts more properties than it should.",
    ),
    "API4": Category(
        "API4",
        "Unrestricted Resource Consumption",
        "CWE-770",
        ["Denial of Service"],
        "medium",
        "No rate limiting, pagination bound, or payload size limit is enforced.",
    ),
    "API5": Category(
        "API5",
        "Broken Function Level Authorization",
        "CWE-285",
        ["Elevation of Privilege"],
        "high",
        "A privileged operation is reachable by callers without the required role.",
    ),
    "API6": Category(
        "API6",
        "Unrestricted Access to Sensitive Business Flows",
        "CWE-840",
        ["Tampering", "Repudiation"],
        "high",
        "A sensitive business flow can be executed without the business "
        "constraints that were specified for it.",
    ),
    "API7": Category(
        "API7",
        "Server Side Request Forgery",
        "CWE-918",
        ["Tampering", "Information Disclosure"],
        "high",
        "A caller-supplied URL is fetched by the server without validation.",
    ),
    "API8": Category(
        "API8",
        "Security Misconfiguration",
        "CWE-16",
        ["Information Disclosure", "Tampering"],
        "medium",
        "Insecure defaults such as debug mode, permissive CORS, or verbose "
        "error output are enabled.",
    ),
    "API9": Category(
        "API9",
        "Improper Inventory Management",
        "CWE-1059",
        ["Information Disclosure"],
        "low",
        "Undocumented, deprecated, or debug endpoints remain exposed.",
    ),
    "API10": Category(
        "API10",
        "Unsafe Consumption of APIs / Injection",
        "CWE-89",
        ["Tampering", "Information Disclosure"],
        "critical",
        "Untrusted input is concatenated into a query, command, or downstream "
        "request instead of being parameterised.",
    ),
}

DEFAULT_CATEGORY = "API8"

_ALIASES = {
    "bola": "API1",
    "broken object level authorization": "API1",
    "idor": "API1",
    "broken authentication": "API2",
    "broken auth": "API2",
    "authentication": "API2",
    "excessive data exposure": "API3",
    "broken object property level authorization": "API3",
    "resource consumption": "API4",
    "rate limit": "API4",
    "bfla": "API5",
    "broken function level authorization": "API5",
    "business flow": "API6",
    "business logic": "API6",
    "ssrf": "API7",
    "server side request forgery": "API7",
    "security misconfiguration": "API8",
    "misconfiguration": "API8",
    "inventory": "API9",
    "injection": "API10",
    "sql injection": "API10",
    "sqli": "API10",
    "command injection": "API10",
}


def normalise_category(raw: str | None) -> str:
    """Map a free-form model or tool label onto a canonical category id."""
    if not raw:
        return DEFAULT_CATEGORY
    text = str(raw).strip()
    upper = text.upper().replace("API:", "API").replace("API-", "API").replace(" ", "")
    for cid in CATEGORIES:
        if upper.startswith(cid) and not (cid == "API1" and upper.startswith("API10")):
            return cid
    if upper.startswith("API10"):
        return "API10"
    lowered = text.lower()
    for alias, cid in _ALIASES.items():
        if alias in lowered:
            return cid
    return DEFAULT_CATEGORY


def category(cid: str) -> Category:
    return CATEGORIES.get(cid, CATEGORIES[DEFAULT_CATEGORY])
