"""Scan orchestration: the five-layer pipeline, end to end.

Order matters and is not arbitrary:

parse -> static -> reasoning (fed the static findings) -> runtime (fed the
candidates the first three layers raised) -> fusion -> classification and
scoring -> remediation -> persistence.

Each layer's status is written to the ``scans`` row as it completes, so the
dashboard can show honest per-layer progress and, critically, can show that a
layer *degraded* (model offline, target unreachable) rather than silently
reporting fewer findings.

A scan runs in a background thread with its own database session. It never
raises into the request that started it: any failure is recorded on the scan
row and surfaced in the UI.
"""

from __future__ import annotations

import logging
import threading
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.analysis_types import LayerFinding
from app.config import settings
from app.db.models import CodeArtifact, Endpoint, Evidence, Finding, Project, RuntimeTest, Scan
from app.db.session import session_scope
from app.llm_layer import run_llm_layer
from app.owasp import category as owasp_category
from app.parser import enrich_with_openapi, parse_openapi, parse_source_files
from app.parser.fastapi_parser import ParsedEndpoint
from app.parser.openapi_parser import SpecError
from app.remediation import generate_remediation
from app.risk_engine import fuse_findings
from app.runtime_layer import TargetNotAllowed, run_runtime_layer
from app.static_layer import run_static_layer
from app.web_layer import run_web_discovery

logger = logging.getLogger("apisentinel.scan")


# --------------------------------------------------------------------------- helpers
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _set_layer(db: Session, scan: Scan, layer: str, **fields: Any) -> None:
    status = dict(scan.layer_status or {})
    entry = dict(status.get(layer) or {})
    entry.update(fields)
    status[layer] = entry
    scan.layer_status = status
    db.add(scan)
    db.commit()


def _parsed_from_rows(rows: Sequence[Endpoint]) -> List[ParsedEndpoint]:
    return [
        ParsedEndpoint(
            method=row.method,
            path=row.path,
            handler_name=row.handler_name,
            source_file=row.source_file,
            source_code=row.source_code,
            line_start=row.line_start,
            line_end=row.line_end,
            auth_dependencies=list(row.auth_dependencies or []),
            path_params=list(row.path_params or []),
            response_model=row.response_model,
            spec_summary=row.spec_summary,
        )
        for row in rows
    ]


def _persist_endpoints(
    db: Session, project_id: uuid.UUID, endpoints: Sequence[ParsedEndpoint], *, discovered_via: str = "source"
) -> None:
    """Replace a project's persisted endpoint set with ``endpoints``.

    Factored out so both the source-mode parser (below) and URL-mode web
    discovery (see ``execute_scan``) write through the exact same path — the
    dashboard's endpoint list, and every downstream layer that reads
    ``Endpoint`` rows back out of the database, does not need to know or care
    which mode produced them.
    """
    db.execute(delete(Endpoint).where(Endpoint.project_id == project_id))
    db.flush()
    for parsed in endpoints:
        db.add(
            Endpoint(
                project_id=project_id,
                method=parsed.method,
                path=parsed.path,
                handler_name=parsed.handler_name,
                source_file=parsed.source_file,
                source_code=parsed.source_code,
                line_start=parsed.line_start,
                line_end=parsed.line_end,
                auth_dependencies=parsed.auth_dependencies,
                path_params=parsed.path_params,
                response_model=parsed.response_model,
                spec_summary=parsed.spec_summary,
                discovered_via=discovered_via,
            )
        )
    db.commit()


def reparse_project(db: Session, project: Project) -> tuple[List[ParsedEndpoint], List[str]]:
    """Parse the project's artifacts and replace its persisted endpoint set."""
    sources = [(a.filename, a.content) for a in project.artifacts if a.kind == "source"]
    endpoints, warnings = parse_source_files(sources)

    spec_raw = project.openapi_spec or next(
        (a.content for a in project.artifacts if a.kind == "openapi"), None
    )
    if spec_raw:
        try:
            endpoints = enrich_with_openapi(endpoints, parse_openapi(spec_raw))
        except SpecError as exc:
            warnings.append(str(exc))

    _persist_endpoints(db, project.id, endpoints, discovered_via="source")
    return endpoints, warnings


# --------------------------------------------------------------------------- pipeline
def execute_scan(scan_id: uuid.UUID) -> None:
    """Run the whole pipeline for one scan. Safe to call in a worker thread."""
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            logger.warning("scan %s disappeared before execution", scan_id)
            return
        project = db.get(Project, scan.project_id)
        if project is None:
            scan.status = "failed"
            scan.error = "The project was deleted before the scan started."
            scan.finished_at = _now()
            return

        options = dict(scan.options or {})
        scan.status = "running"
        scan.layer_status = {
            "parser": {"status": "pending"},
            "static": {"status": "pending"},
            "llm": {"status": "pending"},
            "runtime": {"status": "pending"},
            "risk_engine": {"status": "pending"},
        }
        db.add(scan)
        db.commit()

        all_findings: List[LayerFinding] = []

        try:
            # ---------------------------------------------------------- parser
            # "parser" answers one question regardless of mode: what endpoints
            # does this project have? In source mode that comes from parsing
            # uploaded code; in url/hybrid mode it comes from black-box
            # discovery against a live target (app.web_layer). Both paths
            # write through the same `_persist_endpoints` helper, so every
            # layer below this point — static, LLM, runtime, risk engine —
            # runs completely unchanged either way.
            scan_mode = (project.scan_mode or "source").strip().lower()
            _set_layer(db, scan, "parser", status="running", source_mode=scan_mode)

            endpoints: List[ParsedEndpoint] = []
            parse_warnings: List[str] = []
            web_findings: List[LayerFinding] = []
            web_detail: Dict[str, Any] = {}

            if scan_mode in {"source", "hybrid"}:
                source_endpoints, source_warnings = reparse_project(db, project)
                endpoints.extend(source_endpoints)
                parse_warnings.extend(source_warnings)
                if scan_mode == "source":
                    _persist_endpoints(db, project.id, endpoints, discovered_via="source")

            if scan_mode in {"url", "hybrid"}:
                target = project.runtime_base_url
                if not target:
                    parse_warnings.append(
                        "scan_mode is 'url'/'hybrid' but the project has no target URL "
                        "(runtime_base_url). Set one before scanning."
                    )
                else:
                    effective_scope = dict(project.scope_config or {})
                    for key in (
                        "run_active_scan", "use_zap_spider", "run_active_probes",
                        "use_playwright", "js_max_pages",
                    ):
                        # options[key] is None when the scan request left this
                        # field unset, in which case the project's own
                        # scope_config default (if any) should win rather than
                        # being overwritten by None.
                        if options.get(key) is not None:
                            effective_scope[key] = options[key]
                    try:
                        discovery = run_web_discovery(
                            target,
                            scope_config=effective_scope,
                            allow_public=None if project.target_authorized else False,
                        )
                        existing_keys = {e.key for e in endpoints}
                        for endpoint in discovery.endpoints:
                            if endpoint.key not in existing_keys:
                                endpoints.append(endpoint)
                                existing_keys.add(endpoint.key)
                        web_findings = list(discovery.layer_result.findings)
                        parse_warnings.extend(discovery.layer_result.warnings)
                        web_detail = dict(discovery.layer_result.detail)
                        _persist_endpoints(
                            db,
                            project.id,
                            endpoints,
                            discovered_via="hybrid" if scan_mode == "hybrid" else "web",
                        )
                    except TargetNotAllowed as exc:
                        # A failed authorization/SSRF check stops the scan
                        # outright rather than silently continuing with zero
                        # web-discovered endpoints: this is the security
                        # control the review asked for, not a soft degrade.
                        raise

            all_findings.extend(web_findings)
            _set_layer(
                db,
                scan,
                "parser",
                status="ok" if endpoints else "degraded",
                endpoints=len(endpoints),
                warnings=parse_warnings,
                source_mode=scan_mode,
                message=(
                    None
                    if endpoints
                    else "No endpoints were found — check the uploaded source or the target URL."
                ),
                **web_detail,
            )

            files = [(a.filename, a.content) for a in project.artifacts if a.kind == "source"]

            # ---------------------------------------------------------- static
            static_findings: List[LayerFinding] = []
            if options.get("run_static", True):
                _set_layer(db, scan, "static", status="running")
                static_result = run_static_layer(files, endpoints)
                static_findings = static_result.findings
                all_findings.extend(static_findings)
                _set_layer(
                    db,
                    scan,
                    "static",
                    status="ok" if static_result.ok else "degraded",
                    findings=len(static_findings),
                    duration_seconds=round(static_result.duration_seconds, 2),
                    warnings=static_result.warnings,
                    tools=static_result.detail.get("tools"),
                )
            else:
                _set_layer(db, scan, "static", status="skipped")

            # ------------------------------------------------------------- llm
            if options.get("run_llm", True) and settings.llm_enabled:
                _set_layer(db, scan, "llm", status="running", progress=0)

                def _progress(done: int, total: int) -> None:
                    with session_scope() as progress_db:
                        live = progress_db.get(Scan, scan_id)
                        if live is not None:
                            _set_layer(
                                progress_db,
                                live,
                                "llm",
                                status="running",
                                progress=done,
                                total=total,
                            )

                llm_result = run_llm_layer(
                    endpoints,
                    static_findings,
                    project.business_rules,
                    progress=_progress,
                )
                all_findings.extend(llm_result.findings)
                _set_layer(
                    db,
                    scan,
                    "llm",
                    status="ok" if llm_result.ok else "degraded",
                    findings=len(llm_result.findings),
                    duration_seconds=round(llm_result.duration_seconds, 2),
                    warnings=llm_result.warnings,
                    provider=llm_result.detail.get("provider"),
                    model=llm_result.detail.get("model"),
                    business_rules=llm_result.detail.get("business_rules"),
                )
            else:
                _set_layer(
                    db,
                    scan,
                    "llm",
                    status="skipped",
                    message=(
                        "Reasoning layer disabled by configuration."
                        if not settings.llm_enabled
                        else "Not requested for this scan."
                    ),
                )

            # --------------------------------------------------------- runtime
            runtime_findings: List[LayerFinding] = []
            if options.get("run_runtime"):
                _set_layer(db, scan, "runtime", status="running")
                base_url = options.get("runtime_base_url") or project.runtime_base_url
                credentials = options.get("runtime_credentials") or project.runtime_credentials
                runtime_result = run_runtime_layer(base_url, credentials, all_findings)
                runtime_findings = runtime_result.findings
                all_findings.extend(runtime_findings)
                _set_layer(
                    db,
                    scan,
                    "runtime",
                    status="ok" if runtime_result.ok else "degraded",
                    findings=len(runtime_findings),
                    duration_seconds=round(runtime_result.duration_seconds, 2),
                    warnings=runtime_result.warnings,
                    **{
                        k: v
                        for k, v in runtime_result.detail.items()
                        if k in {"base_url", "probes_run", "confirmed", "refuted", "skipped"}
                    },
                )
            else:
                _set_layer(
                    db,
                    scan,
                    "runtime",
                    status="skipped",
                    message="Runtime validation was not requested for this scan.",
                )

            # ----------------------------------------------------- risk engine
            _set_layer(db, scan, "risk_engine", status="running")
            fused = fuse_findings(all_findings)
            endpoint_ids = {
                f"{row.method} {row.path}": row.id
                for row in db.query(Endpoint).filter(Endpoint.project_id == project.id).all()
            }

            persisted: List[Finding] = []
            for item in fused:
                meta = owasp_category(item.category)
                remediation, remediation_code = generate_remediation(
                    item.category, item.evidence, item.remediation_hint
                )
                finding = Finding(
                    scan_id=scan.id,
                    project_id=project.id,
                    endpoint_id=endpoint_ids.get(item.endpoint_key or ""),
                    title=item.title,
                    owasp_category=item.category,
                    owasp_title=meta.title,
                    cwe=meta.cwe,
                    stride=item.stride,
                    severity=item.severity,
                    risk_score=item.risk_score,
                    confidence=item.confidence,
                    status="open",
                    needs_manual_review=item.needs_manual_review,
                    description=item.description,
                    remediation=remediation,
                    remediation_code=remediation_code,
                    business_rule_ref=item.business_rule_ref,
                    method=item.method,
                    path=item.path,
                    source_file=item.source_file,
                    line_start=item.line_start,
                )
                db.add(finding)
                db.flush()
                persisted.append(finding)

                for evidence in item.evidence:
                    db.add(
                        Evidence(
                            finding_id=finding.id,
                            source=evidence.source,
                            tool=evidence.tool,
                            confidence=evidence.confidence,
                            summary=evidence.title[:1000],
                            detail={
                                "description": evidence.description[:4000],
                                "severity": evidence.severity,
                                **{
                                    k: v
                                    for k, v in (evidence.detail or {}).items()
                                    if k != "reasoning_trace"
                                },
                                **(
                                    {"reasoning_trace": evidence.detail.get("reasoning_trace")}
                                    if evidence.detail and evidence.detail.get("reasoning_trace")
                                    else {}
                                ),
                            },
                        )
                    )
                    if evidence.source == "runtime" and evidence.tool == "httpx-differential":
                        db.add(
                            RuntimeTest(
                                scan_id=scan.id,
                                finding_id=finding.id,
                                name=evidence.title[:200],
                                target_url=str((evidence.detail or {}).get("url")
                                               or ((evidence.detail or {}).get("probe_request") or {}).get("url")
                                               or options.get("runtime_base_url")
                                               or project.runtime_base_url
                                               or ""),
                                outcome="confirmed" if evidence.confirmed else "refuted",
                                confirmed=evidence.confirmed,
                                confidence=evidence.confidence,
                                detail=evidence.detail,
                            )
                        )
            db.commit()

            _set_layer(
                db,
                scan,
                "risk_engine",
                status="ok",
                fused_findings=len(persisted),
                raw_signals=len(all_findings),
            )

            scan.stats = {
                "endpoints": len(endpoints),
                "raw_signals": len(all_findings),
                "findings": len(persisted),
                "runtime_confirmed": len([f for f in fused if f.runtime_confirmed]),
                "runtime_refuted": len([f for f in fused if f.runtime_refuted]),
                "by_severity": _count(persisted, "severity"),
                "by_category": _count(persisted, "owasp_category"),
                "mean_seconds_per_endpoint": (
                    round(
                        sum(
                            (scan.layer_status.get(layer, {}) or {}).get("duration_seconds", 0) or 0
                            for layer in ("static", "llm", "runtime")
                        )
                        / max(1, len(endpoints)),
                        3,
                    )
                ),
            }
            scan.status = "completed"
            scan.finished_at = _now()
            db.add(scan)
            db.commit()

        except Exception as exc:  # noqa: BLE001 - a scan must never crash the worker
            logger.exception("scan %s failed", scan_id)
            scan.status = "failed"
            scan.error = f"{type(exc).__name__}: {exc}"
            scan.stats = {"traceback": traceback.format_exc()[-4000:]}
            scan.finished_at = _now()
            db.add(scan)
            db.commit()


def _count(findings: Sequence[Finding], attribute: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for finding in findings:
        key = str(getattr(finding, attribute))
        out[key] = out.get(key, 0) + 1
    return out


def start_scan(scan_id: uuid.UUID) -> None:
    """Kick the pipeline off on a daemon thread.

    A thread (rather than an external queue) keeps the deliverable to a single
    `docker compose up` with no broker to operate; the work is IO-bound on
    subprocesses and HTTP, so the GIL is not the bottleneck. The scan row is the
    durable state, so a restart mid-scan leaves a visible "running" scan rather
    than losing data.
    """
    thread = threading.Thread(target=execute_scan, args=(scan_id,), daemon=True, name=f"scan-{scan_id}")
    thread.start()


def scan_summary(db: Session, scan: Scan) -> Dict[str, Any]:
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    confidences = [f.confidence for f in findings]
    return {
        "total": len(findings),
        "by_severity": _count(findings, "severity"),
        "by_category": _count(findings, "owasp_category"),
        "by_status": _count(findings, "status"),
        "runtime_confirmed": len([f for f in findings if not f.needs_manual_review]),
        "mean_confidence": round(sum(confidences) / len(confidences), 4) if confidences else 0.0,
    }


def stale_scan_guard(db: Session, project_id: uuid.UUID) -> Optional[Scan]:
    """Return an already-running scan for this project, if any."""
    return (
        db.query(Scan)
        .filter(Scan.project_id == project_id, Scan.status.in_(["queued", "running"]))
        .order_by(Scan.started_at.desc())
        .first()
    )
