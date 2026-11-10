"""Unified risk engine — confidence fusion (Chapter 7.4).

Findings from different layers that describe the *same weakness on the same
endpoint* are grouped and reduced to one reported finding carrying all the
evidence. Fusion rules, in the order they are applied:

1. **Independent corroboration raises belief.** Two independent sources are
   combined with a noisy-OR (probabilistic union) rather than by taking the
   maximum. Two 0.7 signals genuinely justify more belief than one 0.7 signal,
   which is exactly what noisy-OR expresses: ``1 - Π(1 - cᵢ)``.
2. **Runtime confirmation dominates.** A confirmed differential test pins the
   result at 0.95-0.98 and clears the manual-review flag: the vulnerability has
   been demonstrated, not inferred.
3. **Runtime refutation demotes.** If the live system proves the control *is*
   enforced, the finding is capped at low confidence and marked as likely false
   positive, which is how the runtime layer pays for itself.
4. **Unsupported model output stays provisional.** An LLM-only or STRIDE-only
   finding is capped below the corroborated band and always flagged for manual
   review, per the report's requirement that uncorroborated LLM output must not
   be presented as confirmed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from app.analysis_types import LayerFinding
from app.owasp import category as owasp_category
from app.risk_engine.scoring import escalate, risk_score

# Source weights: how much a single source of this kind is trusted on its own.
SOURCE_WEIGHT = {
    "static": 1.0,
    "llm": 1.0,
    "business_rule": 1.0,
    "stride": 0.75,
    "runtime": 1.0,
}

LLM_ONLY_CEILING = 0.85
STRIDE_ONLY_CEILING = 0.72
REFUTED_CEILING = 0.25


@dataclass
class FusedFinding:
    category: str
    endpoint_key: str | None
    title: str
    description: str
    severity: str
    confidence: float
    risk_score: float
    stride: List[str]
    cwe: str
    owasp_title: str
    needs_manual_review: bool
    runtime_confirmed: bool
    runtime_refuted: bool
    remediation_hint: str | None
    business_rule_ref: str | None
    source_file: str | None
    line_start: int | None
    method: str | None
    path: str | None
    evidence: List[LayerFinding] = field(default_factory=list)


def _group_key(finding: LayerFinding) -> tuple[str, str]:
    endpoint = finding.endpoint_key or f"file:{finding.source_file}:{finding.line_start}"
    return (finding.category, endpoint)


def _noisy_or(confidences: Sequence[float]) -> float:
    product = 1.0
    for value in confidences:
        product *= 1.0 - max(0.0, min(0.99, value))
    return 1.0 - product


def _best_title(group: Sequence[LayerFinding]) -> str:
    # Prefer the most specific description of the weakness: runtime conclusions
    # are concrete, LLM titles are contextual, tool ids are the least readable.
    order = {"runtime": 0, "business_rule": 1, "llm": 2, "static": 3, "stride": 4}
    ranked = sorted(group, key=lambda f: (order.get(f.source, 9), -len(f.title)))
    return ranked[0].title


def _compose_description(group: Sequence[LayerFinding]) -> str:
    seen: set[str] = set()
    blocks: List[str] = []
    labels = {
        "static": "Static analysis",
        "llm": "Contextual reasoning",
        "business_rule": "Business-rule comparison",
        "stride": "STRIDE design review",
        "runtime": "Runtime validation",
    }
    for finding in group:
        text = (finding.description or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        label = labels.get(finding.source, finding.source)
        blocks.append(f"**{label} ({finding.tool})** — {text}")
    return "\n\n".join(blocks)


def fuse_findings(findings: Sequence[LayerFinding]) -> List[FusedFinding]:
    groups: Dict[tuple[str, str], List[LayerFinding]] = {}
    for finding in findings:
        groups.setdefault(_group_key(finding), []).append(finding)

    fused: List[FusedFinding] = []
    for (category, endpoint), group in groups.items():
        meta = owasp_category(category)
        sources = {f.source for f in group}

        runtime_confirmed = any(f.source == "runtime" and f.confirmed for f in group)
        runtime_present = any(f.source == "runtime" for f in group)
        runtime_refuted = runtime_present and not runtime_confirmed and any(
            f.source == "runtime" and "enforced" in (f.description or "").lower() for f in group
        )

        weighted = [f.confidence * SOURCE_WEIGHT.get(f.source, 1.0) for f in group]
        confidence = _noisy_or(weighted)

        severity = "low"
        for finding in group:
            severity = escalate(severity, finding.severity)

        needs_review = True
        if runtime_confirmed:
            confidence = max(
                confidence, max(f.confidence for f in group if f.source == "runtime")
            )
            confidence = max(0.95, min(0.98, confidence))
            needs_review = False
        elif runtime_refuted:
            confidence = min(confidence, REFUTED_CEILING)
            severity = "low"
        elif sources <= {"stride"}:
            confidence = min(confidence, STRIDE_ONLY_CEILING)
        elif sources <= {"llm", "stride", "business_rule"}:
            confidence = min(confidence, LLM_ONLY_CEILING)
        elif len(sources) >= 2:
            # Corroborated across independent layers but not runtime-verified:
            # trustworthy enough to act on, still short of demonstrated.
            confidence = min(confidence, 0.94)
            needs_review = confidence < 0.90

        method, _, path = (endpoint.partition(" ") if " " in endpoint else ("", "", ""))
        remediation = next(
            (f.remediation_hint for f in group if f.remediation_hint),
            None,
        )
        business_rule = next((f.business_rule_ref for f in group if f.business_rule_ref), None)
        stride = []
        for finding in group:
            for tag in finding.stride:
                if tag not in stride:
                    stride.append(tag)
        source_file = next((f.source_file for f in group if f.source_file), None)
        line_start = next((f.line_start for f in group if f.line_start), None)

        title = _best_title(group)
        if runtime_refuted:
            title = f"[refuted at runtime] {title}"

        fused.append(
            FusedFinding(
                category=category,
                endpoint_key=endpoint if " " in endpoint else None,
                title=title[:300],
                description=_compose_description(group),
                severity=severity,
                confidence=round(confidence, 4),
                risk_score=risk_score(severity, confidence, runtime_confirmed),
                stride=stride or meta.stride,
                cwe=meta.cwe,
                owasp_title=meta.title,
                needs_manual_review=needs_review,
                runtime_confirmed=runtime_confirmed,
                runtime_refuted=runtime_refuted,
                remediation_hint=remediation,
                business_rule_ref=business_rule,
                source_file=source_file,
                line_start=line_start,
                method=method or None,
                path=path or None,
                evidence=list(group),
            )
        )

    fused.sort(key=lambda f: (-f.risk_score, f.category))
    return fused


_WS = re.compile(r"\s+")


def normalise_text(text: str) -> str:
    return _WS.sub(" ", (text or "").strip().lower())
