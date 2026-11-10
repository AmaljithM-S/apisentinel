"""Scan lifecycle: start a scan, poll per-layer progress, read results."""


from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import owned_project, owned_scan
from app.config import settings
from app.db.models import Finding, Project, Scan, User
from app.db.session import get_db
from app.rate_limit import limiter
from app.runtime_layer import TargetNotAllowed, assert_target_allowed
from app.schemas import FindingOut, ScanCreate, ScanOut, ScanSummary
from app.security import current_user
from app.services.scan_service import scan_summary, stale_scan_guard, start_scan

router = APIRouter(prefix="/api", tags=["scans"])


@router.post(
    "/projects/{project_id}/scans", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED
)
@limiter.limit("12/minute")
def create_scan(
    request: Request,
    payload: ScanCreate,
    project: Project = Depends(owned_project),
    db: Session = Depends(get_db),
):
    scan_mode = (project.scan_mode or "source").strip().lower()
    url_mode = scan_mode in {"url", "hybrid"}

    if not project.artifacts and not (url_mode and project.runtime_base_url):
        message = (
            "Add at least one source file to this project before running a scan."
            if not url_mode
            else "Set a target URL on this project (and mark it authorized) before running a scan."
        )
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, message)

    running = stale_scan_guard(db, project.id)
    if running is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "A scan is already running for this project. Wait for it to finish.",
        )

    options = payload.model_dump()

    if url_mode:
        if not project.runtime_base_url:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "This project's scan mode needs a target URL (runtime_base_url).",
            )
        # Fail before the scan starts, exactly like the run_runtime check
        # below: an unauthorized or SSRF-unsafe target must never reach the
        # background job, even to discover that it will be rejected there too.
        try:
            assert_target_allowed(
                project.runtime_base_url,
                allow_public=None if project.target_authorized else False,
            )
        except TargetNotAllowed as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc))

    if payload.run_runtime:
        target = payload.runtime_base_url or project.runtime_base_url
        if not target:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Runtime validation needs the base URL of a running instance of the API.",
            )
        try:
            options["runtime_base_url"] = assert_target_allowed(
                target, allow_public=None if project.target_authorized else False
            )
        except TargetNotAllowed as exc:
            # Fail before the scan starts: probing a host nobody approved is the
            # one irreversible thing this tool can do.
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc))
        options["runtime_credentials"] = payload.runtime_credentials or project.runtime_credentials

    if payload.run_llm and not settings.llm_enabled:
        options["run_llm"] = False

    scan = Scan(project_id=project.id, status="queued", options=options, layer_status={})
    db.add(scan)
    db.commit()
    db.refresh(scan)
    start_scan(scan.id)
    return scan


@router.get("/projects/{project_id}/scans", response_model=List[ScanOut])
def list_scans(project: Project = Depends(owned_project), db: Session = Depends(get_db)):
    return (
        db.query(Scan)
        .filter(Scan.project_id == project.id)
        .order_by(Scan.started_at.desc())
        .limit(50)
        .all()
    )


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan: Scan = Depends(owned_scan)):
    return scan


@router.get("/scans/{scan_id}/summary", response_model=ScanSummary)
def get_summary(scan: Scan = Depends(owned_scan), db: Session = Depends(get_db)):
    return ScanSummary(scan=ScanOut.model_validate(scan), **scan_summary(db, scan))


@router.get("/scans/{scan_id}/findings", response_model=List[FindingOut])
def list_scan_findings(
    scan: Scan = Depends(owned_scan),
    db: Session = Depends(get_db),
    severity: str | None = None,
    category: str | None = None,
    finding_status: str | None = None,
):
    query = db.query(Finding).filter(Finding.scan_id == scan.id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if category:
        query = query.filter(Finding.owasp_category == category)
    if finding_status:
        query = query.filter(Finding.status == finding_status)
    return query.order_by(Finding.risk_score.desc()).all()


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan: Scan = Depends(owned_scan),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    if scan.status == "running":
        raise HTTPException(status.HTTP_409_CONFLICT, "A running scan cannot be deleted.")
    db.delete(scan)
    db.commit()
    return None
