"""Runtime validation layer orchestration.

Runs only the probes that a candidate finding actually justifies:

* API1 candidates      -> differential authorization test
* API2 candidates      -> unauthenticated access test
* API3 candidates      -> live sensitive-field inspection
* whole target         -> optional ZAP passive alerts

Each probe returns confirmed / refuted / inconclusive. "Refuted" is as valuable
as "confirmed": it is what lets the risk engine demote an LLM-only suspicion
instead of leaving a false positive on the dashboard.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Sequence

from app.analysis_types import LayerFinding, LayerResult
from app.owasp import category as owasp_category
from app.runtime_layer.differential import ProbeResult, RuntimeTester
from app.runtime_layer.safety import TargetNotAllowed
from app.runtime_layer.zap_client import ZapClient

PROBE_CATEGORIES = {"API1", "API2", "API3", "API5"}


def _candidates(findings: Sequence[LayerFinding]) -> List[tuple[str, str, str]]:
    """Unique (category, method, path) triples worth probing."""
    seen: set[tuple[str, str, str]] = set()
    out: List[tuple[str, str, str]] = []
    for finding in findings:
        if finding.category not in PROBE_CATEGORIES or not finding.endpoint_key:
            continue
        method, _, path = finding.endpoint_key.partition(" ")
        if finding.category in {"API1", "API5"} and "{" not in path:
            # The differential BOLA probe substitutes a second user's id into a
            # path placeholder and compares the two responses; with no
            # placeholder there is nothing to substitute, so the "control" and
            # "probe" requests would hit the exact identical URL and trivially
            # match — a false "confirmed" result, not a real test. API5
            # candidates without a placeholder (e.g. a flat admin route) are
            # still worth a BOLA-style probe only when they do have one; this
            # just skips the degenerate case rather than reporting a vacuous
            # confirmation.
            continue
        key = (finding.category, method, path)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _to_finding(category: str, method: str, path: str, probe: ProbeResult) -> LayerFinding:
    meta = owasp_category(category)
    return LayerFinding(
        source="runtime",
        tool="httpx-differential",
        category=category,
        title=probe.name[:280],
        description=str(probe.detail.get("conclusion") or probe.detail.get("reason") or probe.name),
        severity=meta.base_severity,
        confidence=probe.confidence,
        endpoint_key=f"{method} {path}",
        stride=meta.stride,
        detail=probe.detail,
        confirmed=probe.confirmed,
    )


def run_runtime_layer(
    base_url: Optional[str],
    credentials: Optional[Dict[str, Any]],
    candidate_findings: Sequence[LayerFinding],
    *,
    use_zap: bool = True,
) -> LayerResult:
    started = time.monotonic()
    result = LayerResult()

    if not base_url:
        result.ok = False
        result.warnings.append(
            "Runtime validation was requested but no target base URL was provided. Static and "
            "reasoning findings are reported without runtime confirmation."
        )
        return result

    try:
        tester = RuntimeTester(base_url, credentials)
    except TargetNotAllowed as exc:
        result.ok = False
        result.warnings.append(str(exc))
        return result

    probes: List[ProbeResult] = []
    try:
        authenticated = tester.authenticate()
        result.warnings.extend(tester.warnings)
        if not authenticated:
            result.warnings.append(
                "No test account could be authenticated, so only unauthenticated probes ran."
            )

        for category, method, path in _candidates(candidate_findings):
            if category in {"API1", "API5"}:
                probe = tester.probe_bola(method, path)
            elif category == "API2":
                probe = tester.probe_missing_auth(method, path)
            else:
                probe = tester.probe_sensitive_fields(method, path)
            probes.append(probe)
            if probe.outcome != "skipped":
                result.findings.append(_to_finding(category, method, path, probe))
            else:
                result.warnings.append(f"{probe.name}: {probe.detail.get('reason', 'skipped')}")
    finally:
        tester.close()

    if use_zap:
        zap = ZapClient()
        if zap.configured and zap.available():
            zap_findings = zap.passive_scan(tester.base_url)
            result.findings.extend(zap_findings)
            result.detail["zap_alerts"] = len(zap_findings)
        elif zap.configured:
            result.warnings.append(
                "OWASP ZAP is configured but not reachable; differential tests ran without it."
            )

    result.duration_seconds = time.monotonic() - started
    result.detail.update(
        {
            "base_url": tester.base_url,
            "probes_run": len([p for p in probes if p.outcome != "skipped"]),
            "confirmed": len([p for p in probes if p.confirmed]),
            "refuted": len([p for p in probes if p.outcome == "refuted"]),
            "skipped": len([p for p in probes if p.outcome == "skipped"]),
        }
    )
    return result
