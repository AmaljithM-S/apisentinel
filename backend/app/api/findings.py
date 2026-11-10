"""Finding detail and the analyst review workflow.

Review state is deliberately a first-class column rather than a comment: the
evaluation harness measures precision against analyst decisions, so
``false_positive`` and ``confirmed`` must be queryable data.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import owned_finding, owned_project
from app.db.models import Finding, Project
from app.db.session import get_db
from app.schemas import FindingDetail, FindingOut, FindingStatusUpdate

router = APIRouter(prefix="/api", tags=["findings"])


@router.get("/projects/{project_id}/findings", response_model=List[FindingOut])
def list_project_findings(
    project: Project = Depends(owned_project),
    db: Session = Depends(get_db),
):
    return (
        db.query(Finding)
        .filter(Finding.project_id == project.id)
        .order_by(Finding.created_at.desc(), Finding.risk_score.desc())
        .limit(1000)
        .all()
    )


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding: Finding = Depends(owned_finding)):
    return finding


@router.patch("/findings/{finding_id}/status", response_model=FindingDetail)
def update_status(
    payload: FindingStatusUpdate,
    finding: Finding = Depends(owned_finding),
    db: Session = Depends(get_db),
):
    finding.status = payload.status
    # An analyst decision supersedes the model's uncertainty flag either way:
    # confirming or dismissing a finding is itself the manual review.
    if payload.status in {"confirmed", "false_positive", "fixed"}:
        finding.needs_manual_review = False
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding
