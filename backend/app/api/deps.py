"""Shared router dependencies.

``owned_project`` is the single place object-level authorisation happens for
project-scoped resources. Every route that touches a project goes through it, so
the framework cannot ship the very BOLA flaw it is built to detect.
"""

from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.models import Finding, Project, Scan, User
from app.db.session import get_db
from app.security import current_user

NOT_FOUND = "Not found"


def owned_project(
    project_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> Project:
    project = db.get(Project, project_id)
    # 404 rather than 403: a 403 would confirm that someone else's project id exists.
    if project is None or (project.owner_id != user.id and user.role != "admin"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, NOT_FOUND)
    return project


def owned_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, NOT_FOUND)
    project = db.get(Project, scan.project_id)
    if project is None or (project.owner_id != user.id and user.role != "admin"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, NOT_FOUND)
    return scan


def owned_finding(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, NOT_FOUND)
    project = db.get(Project, finding.project_id)
    if project is None or (project.owner_id != user.id and user.role != "admin"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, NOT_FOUND)
    return finding
