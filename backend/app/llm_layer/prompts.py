"""Prompt templates for the reasoning layer.

These implement Appendix A of the report verbatim in structure: a four-step
pipeline, a requirement-aware comparison prompt, and a STRIDE design-review
prompt. Every prompt is schema-constrained — the model is asked for a fixed JSON
shape rather than free text — because unconstrained generation is the primary
source of hallucinated findings.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from app.parser.fastapi_parser import ParsedEndpoint

SYSTEM = (
    "You are a precise API security reviewer. You analyse one HTTP endpoint at a "
    "time and reply with a single JSON object matching the requested schema. "
    "You never invent code that is not shown to you. If the evidence for a "
    "conclusion is weak, you lower the confidence value rather than asserting it. "
    "Absence of a control counts as evidence only when the code you were given "
    "would plainly have to contain it."
)


def endpoint_context(
    endpoint: ParsedEndpoint, static_findings: Optional[List[Dict[str, Any]]] = None
) -> str:
    parts = [
        f"METHOD: {endpoint.method}",
        f"PATH: {endpoint.path}",
        f"HANDLER: {endpoint.handler_name}",
        f"FILE: {endpoint.source_file}:{endpoint.line_start}",
        f"PATH PARAMETERS: {', '.join(endpoint.path_params) or 'none'}",
        f"INJECTED DEPENDENCIES: {', '.join(endpoint.auth_dependencies) or 'none'}",
        f"DECLARED response_model: {endpoint.response_model or 'none'}",
    ]
    if endpoint.spec_summary:
        parts.append(f"OPENAPI SUMMARY: {endpoint.spec_summary}")
    if static_findings:
        parts.append(
            "STATIC ANALYSIS FINDINGS FOR THIS ENDPOINT:\n"
            + json.dumps(static_findings, indent=2)[:2500]
        )
    parts.append("SOURCE CODE:\n```python\n" + endpoint.source_code[:6000] + "\n```")
    return "\n".join(parts)


STEP1 = """Step 1 of 4 — PURPOSE.

{context}

Describe this endpoint's business purpose in one sentence, based on the route,
the handler name, the data model and the specification summary.

Reply as JSON:
{{"purpose": "<one sentence>", "reads_or_writes": "read" | "write" | "both",
  "handles_sensitive_data": true | false, "actor": "<who is expected to call it>"}}"""


STEP2 = """Step 2 of 4 — EXPECTED CONTROLS.

Endpoint purpose: {purpose}
Actor: {actor}

{context}

Given that purpose, list the authentication, authorization, input-validation and
data-exposure controls a correctly implemented version of this endpoint must
enforce. List only controls that genuinely apply to this endpoint.

Reply as JSON:
{{"expected_controls": [
   {{"control": "<short name>", "why": "<one sentence>",
     "kind": "authentication" | "authorization" | "validation" | "data_exposure" | "rate_limiting"}}
 ]}}"""


STEP3 = """Step 3 of 4 — VERIFICATION.

Expected controls:
{controls}

{context}

Inspect ONLY the source code above. For each expected control state whether it
is present, partially present, or missing, and quote the exact line or lines
that justify your answer. If you cannot find evidence either way, say
"unknown" — do not guess.

Reply as JSON:
{{"verification": [
   {{"control": "<name from the list>",
     "status": "present" | "partial" | "missing" | "unknown",
     "evidence": "<quoted code or 'no code implements this'>"}}
 ]}}"""


STEP4 = """Step 4 of 4 — CLASSIFICATION.

Verification results:
{verification}

{context}

For each control that is missing or only partially present and that creates a
real security weakness, produce one finding. Map each to the OWASP API Security
Top 10 (2023) category id: API1 Broken Object Level Authorization, API2 Broken
Authentication, API3 Broken Object Property Level Authorization / Excessive Data
Exposure, API4 Unrestricted Resource Consumption, API5 Broken Function Level
Authorization, API6 Unrestricted Access to Sensitive Business Flows, API7 SSRF,
API8 Security Misconfiguration, API9 Improper Inventory Management, API10 Unsafe
Consumption of APIs / Injection.

Return an empty list if the endpoint is correctly implemented. Do not report
style issues, missing tests, or hypothetical problems that the code does not
exhibit.

Reply as JSON:
{{"findings": [
   {{"title": "<short specific title>",
     "owasp_category": "API1".."API10",
     "severity": "low" | "medium" | "high" | "critical",
     "confidence": 0.0-1.0,
     "description": "<what is wrong and why it matters, referencing the code>",
     "evidence": "<quoted code or 'control absent from handler'>",
     "stride": ["Spoofing" | "Tampering" | "Repudiation" | "Information Disclosure" | "Denial of Service" | "Elevation of Privilege"],
     "remediation": "<concrete fix>",
     "remediation_code": "<short corrected snippet, or empty string>"}}
 ]}}"""


BUSINESS_RULES = """Requirement-aware comparison.

BUSINESS REQUIREMENTS:
{rules}

{context}

Task: compare the implementation against each numbered requirement above. For
each requirement, state whether it is enforced, partially enforced, or not
enforced, and explain the specific code evidence for your judgment. Only
requirements that plausibly apply to THIS endpoint should be judged; mark the
rest "not_applicable".

A requirement that applies and is not enforced is a business logic flaw even
when the code contains no syntactic error and all access-control checks pass.

Reply as JSON:
{{"requirements": [
   {{"requirement": "<the requirement text>",
     "status": "enforced" | "partial" | "not_enforced" | "not_applicable",
     "evidence": "<code evidence for the judgment>",
     "owasp_category": "API1".."API10",
     "severity": "low" | "medium" | "high" | "critical",
     "confidence": 0.0-1.0,
     "impact": "<what an attacker or careless user can do>",
     "remediation": "<concrete fix>"}}
 ]}}"""


STRIDE = """STRIDE design review.

{context}

Do not look for known vulnerability patterns. Instead reason from first
principles about this endpoint's design using the STRIDE categories:
Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service,
Elevation of Privilege.

For each category that reveals a plausible design-level weakness in THIS
endpoint, describe the weakness and the missing control. Skip categories that
do not apply. Report at most four items, and only those you would defend in a
design review.

Reply as JSON:
{{"threats": [
   {{"stride": "<one STRIDE category>",
     "weakness": "<the design-level weakness>",
     "missing_control": "<the control that should exist>",
     "owasp_category": "API1".."API10",
     "severity": "low" | "medium" | "high" | "critical",
     "confidence": 0.0-1.0,
     "remediation": "<concrete fix>"}}
 ]}}"""
