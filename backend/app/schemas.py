"""Pydantic request/response contracts.

Every inbound payload is validated here, so handlers never see unchecked data.
Every outbound payload is an explicit response model, so internal columns
(password hashes, raw provider errors) cannot leak by accident.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, computed_field, field_validator

SEVERITIES = ("low", "medium", "high", "critical")
FINDING_STATUSES = ("open", "confirmed", "false_positive", "fixed")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- auth
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=72)


class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=1, max_length=72)


class UserOut(ORMModel):
    id: uuid.UUID
    email: str
    role: str
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    user: UserOut


# ------------------------------------------------------------------------ project
class ArtifactIn(BaseModel):
    filename: str = Field(min_length=1, max_length=500)
    content: str = Field(min_length=1)
    kind: Literal["source", "openapi"] = "source"

    @field_validator("filename")
    @classmethod
    def _safe_filename(cls, value: str) -> str:
        cleaned = value.replace("\\", "/").strip()
        if cleaned.startswith("/") or ".." in cleaned:
            raise ValueError("filename must be a relative path without '..'")
        return cleaned


ScanMode = Literal["source", "url", "hybrid"]


class ScopeConfig(BaseModel):
    """Options for URL-based (black-box) discovery. All optional; unset
    fields fall back to the operator's defaults (see app.config.Settings)."""

    max_pages: Optional[int] = Field(default=None, ge=1, le=500)
    max_depth: Optional[int] = Field(default=None, ge=1, le=20)
    include_patterns: Optional[List[str]] = None
    exclude_patterns: Optional[List[str]] = None
    run_active_probes: Optional[bool] = None
    use_zap_spider: Optional[bool] = None
    # Intrusive: sends real attack payloads. Requires the operator to also
    # have set ZAP_ENABLE_ACTIVE_SCAN=true; otherwise this is a no-op and the
    # scan records a warning explaining why nothing happened.
    run_active_scan: Optional[bool] = None
    # Renders a bounded number of pages in a real headless browser to find
    # links, forms and XHR/fetch calls that only exist after JavaScript runs
    # (e.g. a single-page application). Heavier than every other check here;
    # a no-op with a warning if Playwright/Chromium is not installed.
    use_playwright: Optional[bool] = None
    js_max_pages: Optional[int] = Field(default=None, ge=1, le=50)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=4000)
    business_rules: Optional[str] = Field(default=None, max_length=20000)
    openapi_spec: Optional[str] = Field(default=None, max_length=400000)
    runtime_base_url: Optional[str] = Field(default=None, max_length=500)
    runtime_credentials: Optional[Dict[str, Any]] = None
    artifacts: List[ArtifactIn] = Field(default_factory=list)
    scan_mode: ScanMode = "source"
    # Required to be explicitly true when scan_mode is "url"/"hybrid" and the
    # target is not on the operator's static allowlist — see
    # app.api.projects.create_project for the enforced rule and
    # app.api.projects' authorization endpoints for how this gets set.
    target_authorized: bool = False
    scope_config: Optional[ScopeConfig] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=4000)
    business_rules: Optional[str] = Field(default=None, max_length=20000)
    openapi_spec: Optional[str] = Field(default=None, max_length=400000)
    runtime_base_url: Optional[str] = Field(default=None, max_length=500)
    runtime_credentials: Optional[Dict[str, Any]] = None
    scan_mode: Optional[ScanMode] = None
    scope_config: Optional[ScopeConfig] = None


class ArtifactOut(ORMModel):
    id: uuid.UUID
    filename: str
    kind: str
    created_at: datetime


class EndpointOut(ORMModel):
    id: uuid.UUID
    method: str
    path: str
    handler_name: str
    source_file: str
    line_start: int
    line_end: int
    auth_dependencies: Optional[List[str]] = None
    path_params: Optional[List[str]] = None
    response_model: Optional[str] = None
    discovered_via: str = "source"


class ProjectOut(ORMModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    business_rules: Optional[str]
    runtime_base_url: Optional[str]
    created_at: datetime
    scan_mode: ScanMode = "source"
    target_authorized: bool = False
    authorization_method: Optional[str] = None
    authorization_confirmed_at: Optional[datetime] = None


class ProjectDetail(ProjectOut):
    artifacts: List[ArtifactOut] = Field(default_factory=list)
    endpoints: List[EndpointOut] = Field(default_factory=list)
    openapi_spec: Optional[str] = None
    runtime_credentials: Optional[Dict[str, Any]] = None
    scope_config: Optional[Dict[str, Any]] = None
    # Shown once, after creation, so the project owner can publish it at
    # /.well-known/apisentinel-authorization.txt on the target to prove
    # authorization automatically; see POST /{id}/authorization/verify.
    authorization_token: Optional[str] = None


# --------------------------------------------------------------------------- scan
class ScanCreate(BaseModel):
    run_static: bool = True
    run_llm: bool = True
    run_runtime: bool = False
    runtime_base_url: Optional[str] = Field(default=None, max_length=500)
    runtime_credentials: Optional[Dict[str, Any]] = None
    # Only meaningful for a scan_mode="url"/"hybrid" project; ignored
    # otherwise. See ScopeConfig for field meanings.
    run_active_probes: Optional[bool] = None
    use_zap_spider: Optional[bool] = None
    run_active_scan: Optional[bool] = None
    use_playwright: Optional[bool] = None
    js_max_pages: Optional[int] = Field(default=None, ge=1, le=50)


class ScanOut(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID
    status: str
    layer_status: Dict[str, Any]
    options: Dict[str, Any]
    stats: Dict[str, Any]
    error: Optional[str]
    started_at: datetime
    finished_at: Optional[datetime]


class EvidenceOut(ORMModel):
    id: uuid.UUID
    source: str
    tool: Optional[str]
    confidence: float
    summary: str
    detail: Optional[Dict[str, Any]]


class RuntimeTestOut(ORMModel):
    id: uuid.UUID
    name: str
    target_url: str
    outcome: str
    confirmed: bool
    confidence: float
    detail: Optional[Dict[str, Any]]


EvidenceLevel = Literal["confirmed", "suspected", "inconclusive"]


class FindingOut(ORMModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    endpoint_id: Optional[uuid.UUID]
    title: str
    owasp_category: str
    owasp_title: str
    cwe: Optional[str]
    stride: Optional[List[str]]
    severity: str
    risk_score: float
    confidence: float
    status: str
    needs_manual_review: bool
    description: str
    remediation: Optional[str]
    remediation_code: Optional[str]
    business_rule_ref: Optional[str]
    method: Optional[str]
    path: Optional[str]
    source_file: Optional[str]
    line_start: Optional[int]
    created_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evidence_level(self) -> EvidenceLevel:
        """A plain-language verdict the dashboard can badge every finding
        with, directly answering the review's request to "clearly identify
        which findings are confirmed, suspected or inconclusive".

        Derived entirely from fields the risk engine already sets
        (``needs_manual_review`` is cleared only on runtime confirmation; a
        runtime-refuted finding is demoted to a low fused confidence) — no
        extra column or fusion-logic change was needed to add this. The
        thresholds are deliberately conservative: Althunayyan et al. (2022)
        found that automated black-box scanners both miss real flaws and
        over-report on weak signals, so "confirmed" is reserved for the
        strongest case the risk engine can produce (see risk_engine.fusion).
        """
        if not self.needs_manual_review and self.confidence >= 0.90:
            return "confirmed"
        if self.confidence < 0.35:
            return "inconclusive"
        return "suspected"


class FindingDetail(FindingOut):
    evidence: List[EvidenceOut] = Field(default_factory=list)
    runtime_tests: List[RuntimeTestOut] = Field(default_factory=list)


class FindingStatusUpdate(BaseModel):
    status: Literal["open", "confirmed", "false_positive", "fixed"]


class RuntimeProbeRequest(BaseModel):
    base_url: str = Field(min_length=1, max_length=500)
    credentials: Optional[Dict[str, Any]] = None


class ScanSummary(BaseModel):
    scan: ScanOut
    total: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    by_status: Dict[str, int]
    runtime_confirmed: int
    mean_confidence: float


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    database: bool
    llm_provider: str
    llm_reachable: Optional[bool] = None
    zap_configured: bool
    version: str
