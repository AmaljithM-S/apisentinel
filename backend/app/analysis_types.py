"""Shared, layer-neutral finding representation.

Each detection layer emits ``LayerFinding`` objects. The risk engine is the only
component that turns them into persisted ``Finding`` rows, which keeps fusion
logic in exactly one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LayerFinding:
    source: str  # static | llm | stride | business_rule | runtime
    tool: str  # bandit | semgrep | structural | ollama:model | httpx | zap
    category: str  # canonical OWASP id, e.g. "API1"
    title: str
    description: str
    severity: str = "medium"
    confidence: float = 0.5
    endpoint_key: Optional[str] = None
    source_file: Optional[str] = None
    line_start: Optional[int] = None
    detail: Dict[str, Any] = field(default_factory=dict)
    stride: List[str] = field(default_factory=list)
    business_rule_ref: Optional[str] = None
    remediation_hint: Optional[str] = None
    confirmed: bool = False


@dataclass
class LayerResult:
    findings: List[LayerFinding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    ok: bool = True
    detail: Dict[str, Any] = field(default_factory=dict)
