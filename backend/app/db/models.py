"""Persistence model for the whole framework.

The schema mirrors the five-layer pipeline: parsed ``Endpoint`` records feed
``Finding`` rows, each backed by one ``Evidence`` row per contributing layer
(static / llm / stride / business_rule / runtime). Keeping evidence separate
from findings is what makes confidence fusion auditable — the dashboard can
always show *why* a fused score is what it is.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    projects: Mapped[list["Project"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    business_rules: Mapped[Optional[str]] = mapped_column(Text)
    openapi_spec: Mapped[Optional[str]] = mapped_column(Text)
    runtime_base_url: Mapped[Optional[str]] = mapped_column(String(500))
    runtime_credentials: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    # --- URL-based (black-box) scanning ---------------------------------
    # "source": the original flow — artifacts uploaded, parsed, scanned.
    # "url": no artifacts; endpoints come entirely from scanning
    #        `runtime_base_url` (app.web_layer). "hybrid": both are merged.
    scan_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="source")
    # Recorded evidence that the project owner is authorized to test
    # `runtime_base_url`, required before a non-allowlisted public host can be
    # scanned at all (see app.runtime_layer.safety.assert_target_allowed and
    # app.api.projects' authorization endpoints). Never implied by scan_mode
    # alone — a url-mode project with target_authorized=False cannot scan a
    # public host regardless of what scan options are requested.
    target_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    authorization_method: Mapped[Optional[str]] = mapped_column(String(32))  # "manual" | "well-known-token"
    authorization_token: Mapped[Optional[str]] = mapped_column(String(64))
    authorization_confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    # {"max_pages": int, "max_depth": int, "include_patterns": [...],
    #  "exclude_patterns": [...], "run_active_probes": bool,
    #  "use_zap_spider": bool, "run_active_scan": bool}
    scope_config: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB)

    owner: Mapped[User] = relationship(back_populates="projects")
    artifacts: Mapped[list["CodeArtifact"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    endpoints: Mapped[list["Endpoint"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class CodeArtifact(Base):
    __tablename__ = "code_artifacts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="source")
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[Project] = relationship(back_populates="artifacts")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    handler_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    source_file: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    source_code: Mapped[str] = mapped_column(Text, nullable=False, default="")
    line_start: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    auth_dependencies: Mapped[Optional[list[str]]] = mapped_column(JSONB)
    path_params: Mapped[Optional[list[str]]] = mapped_column(JSONB)
    response_model: Mapped[Optional[str]] = mapped_column(String(200))
    spec_summary: Mapped[Optional[str]] = mapped_column(Text)
    # "source" | "openapi" | "web" | "form" | "hybrid" — how this endpoint was
    # found, surfaced on the dashboard so a reviewer can see at a glance
    # whether something was read from code or only observed from outside.
    discovered_via: Mapped[str] = mapped_column(String(16), nullable=False, default="source")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[Project] = relationship(back_populates="endpoints")

    __table_args__ = (Index("ix_endpoints_project_method_path", "project_id", "method", "path"),)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    layer_status: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    options: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    error: Mapped[Optional[str]] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    owasp_category: Mapped[str] = mapped_column(String(16), nullable=False, default="API8")
    owasp_title: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    cwe: Mapped[Optional[str]] = mapped_column(String(32))
    stride: Mapped[Optional[list[str]]] = mapped_column(JSONB)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="open")
    needs_manual_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    remediation: Mapped[Optional[str]] = mapped_column(Text)
    remediation_code: Mapped[Optional[str]] = mapped_column(Text)
    business_rule_ref: Mapped[Optional[str]] = mapped_column(Text)
    method: Mapped[Optional[str]] = mapped_column(String(10))
    path: Mapped[Optional[str]] = mapped_column(String(500))
    source_file: Mapped[Optional[str]] = mapped_column(String(500))
    line_start: Mapped[Optional[int]] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    runtime_tests: Mapped[list["RuntimeTest"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    tool: Mapped[Optional[str]] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detail: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class RuntimeTest(Base):
    __tablename__ = "runtime_tests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    target_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False, default="inconclusive")
    confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    detail: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    finding: Mapped[Optional[Finding]] = relationship(back_populates="runtime_tests")


class GroundTruth(Base):
    __tablename__ = "ground_truth"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    dataset: Mapped[str] = mapped_column(String(64), nullable=False, default="custom-fastapi")
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    vulnerable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    owasp_category: Mapped[Optional[str]] = mapped_column(String(16))
    business_rule: Mapped[Optional[str]] = mapped_column(Text)
    notes: Mapped[Optional[str]] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("dataset", "method", "path", name="uq_ground_truth_endpoint"),
    )
