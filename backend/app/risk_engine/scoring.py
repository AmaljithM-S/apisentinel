"""Risk scoring.

Severity alone is too coarse to sort a dashboard: a critical finding nobody has
corroborated should not outrank a high finding proven at runtime. The score
therefore multiplies impact (severity) by belief (fused confidence) and adds a
small bonus for runtime-confirmed evidence, producing a 0-100 ordering that
matches how a security reviewer would actually triage.
"""

from __future__ import annotations

SEVERITY_WEIGHT = {"low": 25.0, "medium": 50.0, "high": 75.0, "critical": 95.0}
SEVERITY_ORDER = ("low", "medium", "high", "critical")


def risk_score(severity: str, confidence: float, runtime_confirmed: bool = False) -> float:
    base = SEVERITY_WEIGHT.get(str(severity).lower(), 50.0)
    score = base * max(0.0, min(1.0, confidence))
    if runtime_confirmed:
        score = min(100.0, score * 1.15)
    return round(score, 2)


def severity_from_score(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def escalate(current: str, candidate: str) -> str:
    """Return the more severe of two severities."""
    try:
        return (
            candidate
            if SEVERITY_ORDER.index(candidate.lower()) > SEVERITY_ORDER.index(current.lower())
            else current
        )
    except ValueError:
        return current
