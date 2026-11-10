"""Four-step reasoning pipeline, requirement-aware pass and STRIDE pass.

Chapter 6 of the report decomposes a single open-ended "find vulnerabilities"
prompt into four narrower steps. That decomposition is the point: each step has
one verifiable job, and the output of each step is fed forward as *given* facts,
so the model never has to hold the whole judgement in one inference.

Confidence produced here is capped at the report's indicative band for LLM
reasoning (0.80–0.85). Only the runtime layer, or corroboration in the risk
engine, can push a finding above that band.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from app.analysis_types import LayerFinding, LayerResult
from app.config import settings
from app.llm_layer import prompts
from app.llm_layer.provider import LLMError, LLMProvider, get_provider
from app.owasp import category as owasp_category
from app.owasp import normalise_category
from app.parser.fastapi_parser import ParsedEndpoint

LLM_CONFIDENCE_FLOOR = 0.60
LLM_CONFIDENCE_CEILING = 0.85

SEVERITIES = ("low", "medium", "high", "critical")
STRIDE_VALUES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)


def _clamp_confidence(raw: Any, default: float = 0.75) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = default
    if value > 1:  # models sometimes answer "85" instead of 0.85
        value = value / 100.0
    return max(LLM_CONFIDENCE_FLOOR, min(LLM_CONFIDENCE_CEILING, value))


def _clean_severity(raw: Any, fallback: str) -> str:
    value = str(raw or "").strip().lower()
    return value if value in SEVERITIES else fallback


def _clean_stride(raw: Any) -> List[str]:
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    out: List[str] = []
    for item in raw:
        text = str(item).strip().lower()
        for known in STRIDE_VALUES:
            if text and (text in known.lower() or known.lower().startswith(text)):
                if known not in out:
                    out.append(known)
                break
    return out


def _numbered_rules(business_rules: Optional[str]) -> List[str]:
    if not business_rules:
        return []
    lines = [line.strip(" \t-*") for line in business_rules.splitlines()]
    rules = [re.sub(r"^\d+[.)]\s*", "", line) for line in lines if line.strip()]
    return rules[:40]


class ReasoningPipeline:
    """Runs all three reasoning passes for one endpoint."""

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider
        self._cache: Dict[str, Dict[str, Any]] = {}

    # -- infrastructure ---------------------------------------------------
    def _ask(self, user: str) -> Dict[str, Any]:
        key = hashlib.sha256(user.encode("utf-8")).hexdigest()
        if key in self._cache:
            return self._cache[key]
        value = self.provider.complete_json(prompts.SYSTEM, user)
        self._cache[key] = value
        return value

    # -- passes -----------------------------------------------------------
    def four_step(
        self, endpoint: ParsedEndpoint, static_findings: List[Dict[str, Any]]
    ) -> tuple[List[LayerFinding], Dict[str, Any]]:
        context = prompts.endpoint_context(endpoint, static_findings)

        step1 = self._ask(prompts.STEP1.format(context=context))
        purpose = str(step1.get("purpose", "")).strip() or "purpose not determined"
        actor = str(step1.get("actor", "")).strip() or "unknown caller"

        step2 = self._ask(
            prompts.STEP2.format(context=context, purpose=purpose, actor=actor)
        )
        controls = step2.get("expected_controls") or []

        step3 = self._ask(
            prompts.STEP3.format(
                context=context, controls=json.dumps(controls, indent=2)[:3000]
            )
        )
        verification = step3.get("verification") or []

        step4 = self._ask(
            prompts.STEP4.format(
                context=context, verification=json.dumps(verification, indent=2)[:3000]
            )
        )

        trace = {
            "step1_purpose": step1,
            "step2_expected_controls": controls,
            "step3_verification": verification,
        }

        findings: List[LayerFinding] = []
        for item in step4.get("findings") or []:
            if not isinstance(item, dict):
                continue
            cid = normalise_category(item.get("owasp_category"))
            meta = owasp_category(cid)
            findings.append(
                LayerFinding(
                    source="llm",
                    tool=f"{self.provider.name}:{self.provider.model}",
                    category=cid,
                    title=str(item.get("title") or f"{meta.title} on {endpoint.key}")[:280],
                    description=str(item.get("description") or meta.description),
                    severity=_clean_severity(item.get("severity"), meta.base_severity),
                    confidence=_clamp_confidence(item.get("confidence"), 0.8),
                    endpoint_key=endpoint.key,
                    source_file=endpoint.source_file,
                    line_start=endpoint.line_start,
                    stride=_clean_stride(item.get("stride")) or meta.stride,
                    detail={
                        "evidence": str(item.get("evidence", ""))[:2000],
                        "reasoning_trace": trace,
                    },
                    remediation_hint=str(item.get("remediation") or "") or None,
                )
            )
            code = str(item.get("remediation_code") or "").strip()
            if code:
                findings[-1].detail["remediation_code"] = code[:4000]
        return findings, trace

    def business_rules(
        self, endpoint: ParsedEndpoint, rules: Sequence[str]
    ) -> List[LayerFinding]:
        if not rules:
            return []
        context = prompts.endpoint_context(endpoint, None)
        numbered = "\n".join(f"{i + 1}. {rule}" for i, rule in enumerate(rules))
        payload = self._ask(prompts.BUSINESS_RULES.format(context=context, rules=numbered))

        findings: List[LayerFinding] = []
        for item in payload.get("requirements") or []:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status", "")).strip().lower()
            if status not in {"not_enforced", "partial"}:
                continue
            cid = normalise_category(item.get("owasp_category") or "API6")
            meta = owasp_category(cid)
            requirement = str(item.get("requirement", "")).strip()
            findings.append(
                LayerFinding(
                    source="business_rule",
                    tool=f"{self.provider.name}:{self.provider.model}",
                    category=cid,
                    title=(
                        f"Business rule {'partially ' if status == 'partial' else 'not '}"
                        f"enforced on {endpoint.key}: {requirement[:120]}"
                    ),
                    description=(
                        f"Stated requirement: {requirement}\n\n"
                        f"Status: {status}\n"
                        f"Impact: {str(item.get('impact', '')).strip()}\n"
                        f"Code evidence: {str(item.get('evidence', '')).strip()}"
                    ),
                    severity=_clean_severity(item.get("severity"), meta.base_severity),
                    confidence=_clamp_confidence(
                        item.get("confidence"), 0.78 if status == "not_enforced" else 0.7
                    ),
                    endpoint_key=endpoint.key,
                    source_file=endpoint.source_file,
                    line_start=endpoint.line_start,
                    stride=meta.stride,
                    business_rule_ref=requirement,
                    detail={"status": status, "evidence": str(item.get("evidence", ""))[:2000]},
                    remediation_hint=str(item.get("remediation") or "") or None,
                )
            )
        return findings

    def stride(self, endpoint: ParsedEndpoint) -> List[LayerFinding]:
        context = prompts.endpoint_context(endpoint, None)
        payload = self._ask(prompts.STRIDE.format(context=context))
        findings: List[LayerFinding] = []
        for item in payload.get("threats") or []:
            if not isinstance(item, dict):
                continue
            cid = normalise_category(item.get("owasp_category"))
            meta = owasp_category(cid)
            stride = _clean_stride(item.get("stride")) or meta.stride
            findings.append(
                LayerFinding(
                    source="stride",
                    tool=f"{self.provider.name}:{self.provider.model}",
                    category=cid,
                    title=f"[{stride[0] if stride else 'Design'}] "
                    + str(item.get("weakness") or meta.title)[:240],
                    description=(
                        f"{str(item.get('weakness', '')).strip()}\n\n"
                        f"Missing control: {str(item.get('missing_control', '')).strip()}"
                    ),
                    severity=_clean_severity(item.get("severity"), "medium"),
                    # Design-level reasoning has no code evidence behind it, so it
                    # is deliberately capped below the code-verified pass.
                    confidence=min(_clamp_confidence(item.get("confidence"), 0.68), 0.75),
                    endpoint_key=endpoint.key,
                    source_file=endpoint.source_file,
                    line_start=endpoint.line_start,
                    stride=stride,
                    detail={"missing_control": str(item.get("missing_control", ""))[:1000]},
                    remediation_hint=str(item.get("remediation") or "") or None,
                )
            )
        return findings


def run_llm_layer(
    endpoints: Sequence[ParsedEndpoint],
    static_findings: Sequence[LayerFinding],
    business_rules_text: Optional[str],
    *,
    provider: Optional[LLMProvider] = None,
    progress: Optional[Callable[[int, int], None]] = None,
    max_endpoints: int = 200,
) -> LayerResult:
    started = time.monotonic()
    result = LayerResult()

    provider = provider or get_provider()
    if not settings.llm_enabled:
        result.ok = False
        result.warnings.append("LLM layer disabled by configuration (LLM_PROVIDER=disabled).")
        return result
    if not provider.available():
        result.ok = False
        result.warnings.append(
            f"LLM provider '{provider.name}' is not reachable. The scan continued with the "
            "static and runtime layers only."
        )
        return result

    rules = _numbered_rules(business_rules_text)
    pipeline = ReasoningPipeline(provider)

    by_endpoint: Dict[str, List[Dict[str, Any]]] = {}
    for finding in static_findings:
        if finding.endpoint_key:
            by_endpoint.setdefault(finding.endpoint_key, []).append(
                {
                    "tool": finding.tool,
                    "category": finding.category,
                    "title": finding.title,
                    "severity": finding.severity,
                }
            )

    targets = list(endpoints)[:max_endpoints]
    if len(endpoints) > max_endpoints:
        result.warnings.append(
            f"Only the first {max_endpoints} endpoints were sent to the reasoning layer."
        )

    failures = 0
    for index, endpoint in enumerate(targets, start=1):
        try:
            findings, _trace = pipeline.four_step(endpoint, by_endpoint.get(endpoint.key, []))
            result.findings.extend(findings)
            result.findings.extend(pipeline.business_rules(endpoint, rules))
            result.findings.extend(pipeline.stride(endpoint))
        except LLMError as exc:
            failures += 1
            result.warnings.append(f"{endpoint.key}: {exc}")
            if failures >= 3:
                result.ok = False
                result.warnings.append(
                    "Reasoning layer stopped after three consecutive provider failures."
                )
                break
        if progress:
            progress(index, len(targets))

    result.duration_seconds = time.monotonic() - started
    result.detail = {
        "provider": provider.name,
        "model": provider.model,
        "endpoints_analysed": len(targets),
        "business_rules": len(rules),
    }
    return result
