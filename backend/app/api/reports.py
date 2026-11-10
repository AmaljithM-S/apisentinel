"""Report export: JSON for tooling, Markdown for humans, SARIF for CI."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.orm import Session

from app.api.deps import owned_scan
from app.db.models import Finding, Project, Scan
from app.db.session import get_db
from app.owasp import CATEGORIES
from app.services.scan_service import scan_summary

router = APIRouter(prefix="/api/scans", tags=["reports"])

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _findings(db: Session, scan: Scan) -> List[Finding]:
    return (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(Finding.risk_score.desc())
        .all()
    )


@router.get("/{scan_id}/report.json")
def json_report(scan: Scan = Depends(owned_scan), db: Session = Depends(get_db)):
    project = db.get(Project, scan.project_id)
    findings = _findings(db, scan)
    payload: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": {"id": str(project.id), "name": project.name} if project else None,
        "scan": {
            "id": str(scan.id),
            "status": scan.status,
            "started_at": scan.started_at.isoformat(),
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "layers": scan.layer_status,
            "stats": scan.stats,
        },
        "summary": scan_summary(db, scan),
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "owasp": {"category": f.owasp_category, "title": f.owasp_title},
                "cwe": f.cwe,
                "stride": f.stride,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "confidence": f.confidence,
                "status": f.status,
                "needs_manual_review": f.needs_manual_review,
                "endpoint": (
                    {"method": f.method, "path": f.path} if f.method and f.path else None
                ),
                "location": {"file": f.source_file, "line": f.line_start},
                "description": f.description,
                "remediation": f.remediation,
                "remediation_code": f.remediation_code,
                "business_rule": f.business_rule_ref,
                "evidence": [
                    {
                        "source": e.source,
                        "tool": e.tool,
                        "confidence": e.confidence,
                        "summary": e.summary,
                        "detail": e.detail,
                    }
                    for e in f.evidence
                ],
                "runtime_tests": [
                    {
                        "name": t.name,
                        "target_url": t.target_url,
                        "outcome": t.outcome,
                        "confirmed": t.confirmed,
                        "confidence": t.confidence,
                    }
                    for t in f.runtime_tests
                ],
            }
            for f in findings
        ],
    }
    return JSONResponse(
        payload,
        headers={"Content-Disposition": f'attachment; filename="apisentinel-{scan.id}.json"'},
    )


@router.get("/{scan_id}/report.md", response_class=PlainTextResponse)
def markdown_report(scan: Scan = Depends(owned_scan), db: Session = Depends(get_db)):
    project = db.get(Project, scan.project_id)
    findings = _findings(db, scan)
    summary = scan_summary(db, scan)

    lines: List[str] = [
        f"# APISentinel security report — {project.name if project else 'project'}",
        "",
        f"* Scan: `{scan.id}`",
        f"* Status: **{scan.status}**",
        f"* Started: {scan.started_at.isoformat()}",
        f"* Findings: **{summary['total']}** "
        f"(mean confidence {summary['mean_confidence']:.2f}, "
        f"{summary['runtime_confirmed']} needing no further review)",
        "",
        "## Layer execution",
        "",
        "| Layer | Status | Findings | Duration (s) | Notes |",
        "| --- | --- | --- | --- | --- |",
    ]
    for layer, label in (
        ("parser", "Parser"),
        ("static", "Static analysis"),
        ("llm", "Contextual reasoning"),
        ("runtime", "Runtime validation"),
        ("risk_engine", "Risk engine"),
    ):
        entry = (scan.layer_status or {}).get(layer) or {}
        notes = "; ".join(entry.get("warnings") or []) or entry.get("message") or ""
        lines.append(
            f"| {label} | {entry.get('status', 'n/a')} | {entry.get('findings', entry.get('endpoints', '—'))} "
            f"| {entry.get('duration_seconds', '—')} | {notes[:180]} |"
        )

    lines += ["", "## Findings by OWASP API category", "", "| Category | Title | Count |", "| --- | --- | --- |"]
    by_category = summary["by_category"]
    for key in CATEGORIES:
        if by_category.get(key):
            lines.append(f"| {key} | {CATEGORIES[key].title} | {by_category[key]} |")

    lines += ["", "## Detail", ""]
    for index, finding in enumerate(findings, start=1):
        endpoint = f"`{finding.method} {finding.path}`" if finding.method else "—"
        lines += [
            f"### {index}. {finding.title}",
            "",
            f"* **Severity:** {finding.severity} · **Risk score:** {finding.risk_score} "
            f"· **Confidence:** {finding.confidence:.2f}",
            f"* **OWASP:** {finding.owasp_category} — {finding.owasp_title} · **CWE:** {finding.cwe or '—'}"
            f" · **STRIDE:** {', '.join(finding.stride or []) or '—'}",
            f"* **Endpoint:** {endpoint} · **Location:** {finding.source_file or '—'}"
            f":{finding.line_start or '—'}",
            f"* **Review state:** {finding.status}"
            + (" (needs manual review)" if finding.needs_manual_review else ""),
            "",
            finding.description or "",
            "",
        ]
        if finding.evidence:
            lines.append("**Evidence**")
            lines.append("")
            for evidence in finding.evidence:
                lines.append(
                    f"* `{evidence.source}` / {evidence.tool or '—'} "
                    f"(confidence {evidence.confidence:.2f}) — {evidence.summary}"
                )
            lines.append("")
        if finding.remediation:
            lines += ["**Remediation**", "", finding.remediation, ""]
        if finding.remediation_code:
            lines += ["```python", finding.remediation_code, "```", ""]

    return PlainTextResponse(
        "\n".join(lines),
        headers={"Content-Disposition": f'attachment; filename="apisentinel-{scan.id}.md"'},
    )


@router.get("/{scan_id}/report.sarif")
def sarif_report(scan: Scan = Depends(owned_scan), db: Session = Depends(get_db)):
    """SARIF 2.1.0 so findings can be uploaded to GitHub code scanning."""
    findings = _findings(db, scan)
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        rule_id = f"apisentinel/{finding.owasp_category}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.owasp_title or finding.owasp_category,
                "shortDescription": {"text": finding.owasp_title or finding.owasp_category},
                "properties": {
                    "tags": ["security", finding.owasp_category, *(finding.stride or [])],
                    "cwe": finding.cwe,
                },
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": f"{finding.title} (confidence {finding.confidence:.2f})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.source_file or "unknown"},
                            "region": {"startLine": max(1, finding.line_start or 1)},
                        }
                    }
                ],
                "properties": {
                    "riskScore": finding.risk_score,
                    "confidence": finding.confidence,
                    "needsManualReview": finding.needs_manual_review,
                    "endpoint": f"{finding.method} {finding.path}" if finding.method else None,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "APISentinel",
                        "informationUri": "https://github.com/apisentinel",
                        "version": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return JSONResponse(
        sarif,
        headers={"Content-Disposition": f'attachment; filename="apisentinel-{scan.id}.sarif"'},
    )
