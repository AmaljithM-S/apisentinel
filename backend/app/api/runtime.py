"""Ad-hoc runtime probing panel.

Separate from the scan pipeline so an analyst can re-verify a single finding
against a live instance without re-running static analysis and the model — the
slow layers — just to confirm a fix. The same allowlist guard applies.
"""


from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import owned_finding, owned_project
from app.db.models import Finding, Project
from app.db.session import get_db
from app.rate_limit import limiter
from app.runtime_layer import TargetNotAllowed
from app.runtime_layer.differential import RuntimeTester
from app.schemas import RuntimeProbeRequest

router = APIRouter(prefix="/api", tags=["runtime"])


def _run(base_url: str, credentials: Dict[str, Any] | None, targets: List[Finding]):
    try:
        tester = RuntimeTester(base_url, credentials)
    except TargetNotAllowed as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc))

    results = []
    try:
        authenticated = tester.authenticate()
        for finding in targets:
            if not finding.method or not finding.path:
                continue
            if finding.owasp_category in {"API1", "API5"}:
                probe = tester.probe_bola(finding.method, finding.path)
            elif finding.owasp_category == "API2":
                probe = tester.probe_missing_auth(finding.method, finding.path)
            else:
                probe = tester.probe_sensitive_fields(finding.method, finding.path)
            results.append(
                {
                    "finding_id": str(finding.id),
                    "name": probe.name,
                    "target_url": probe.target_url,
                    "outcome": probe.outcome,
                    "confirmed": probe.confirmed,
                    "confidence": probe.confidence,
                    "detail": probe.detail,
                }
            )
    finally:
        tester.close()

    return {
        "base_url": tester.base_url,
        "authenticated": authenticated,
        "warnings": tester.warnings,
        "results": results,
    }


@router.post("/findings/{finding_id}/verify")
@limiter.limit("30/minute")
def verify_finding(
    request: Request,
    payload: RuntimeProbeRequest,
    finding: Finding = Depends(owned_finding),
):
    if not finding.method or not finding.path:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "This finding is not tied to a specific endpoint, so it cannot be probed live.",
        )
    return _run(payload.base_url, payload.credentials, [finding])


@router.post("/projects/{project_id}/verify")
@limiter.limit("6/minute")
def verify_project(
    request: Request,
    payload: RuntimeProbeRequest,
    project: Project = Depends(owned_project),
    db: Session = Depends(get_db),
):
    findings = (
        db.query(Finding)
        .filter(
            Finding.project_id == project.id,
            Finding.owasp_category.in_(["API1", "API2", "API3", "API5"]),
            Finding.status.in_(["open", "confirmed"]),
        )
        .order_by(Finding.risk_score.desc())
        .limit(40)
        .all()
    )
    if not findings:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "There are no runtime-testable findings to verify for this project yet.",
        )
    return _run(payload.base_url, payload.credentials, findings)
