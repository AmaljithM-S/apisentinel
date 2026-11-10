"""Project CRUD plus source ingestion (raw files, ZIP archives, Git clones)."""

from __future__ import annotations

import io
import logging
import os
import secrets
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import CodeArtifact, Project, User
from app.db.session import get_db
from app.runtime_layer import TargetNotAllowed, assert_target_allowed
from app.schemas import (
    ArtifactIn,
    EndpointOut,
    ProjectCreate,
    ProjectDetail,
    ProjectOut,
    ProjectUpdate,
)
from app.security import current_user
from app.services.scan_service import reparse_project
from app.api.deps import owned_project

router = APIRouter(prefix="/api/projects", tags=["projects"])
logger = logging.getLogger("apisentinel.projects")

SOURCE_SUFFIXES = {".py"}
SPEC_SUFFIXES = {".json", ".yaml", ".yml"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "site-packages", ".mypy_cache"}
MAX_FILES = 400


def _decode(raw: bytes, filename: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"'{filename}' is not UTF-8 text; only source files can be analysed.",
        )


def _classify(name: str) -> str | None:
    suffix = Path(name).suffix.lower()
    if suffix in SOURCE_SUFFIXES:
        return "source"
    if suffix in SPEC_SUFFIXES:
        return "openapi"
    return None


def _collect_tree(root: Path) -> List[ArtifactIn]:
    artifacts: List[ArtifactIn] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        kind = _classify(path.name)
        if kind is None:
            continue
        rel = path.relative_to(root).as_posix()
        try:
            content = path.read_text("utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if not content.strip():
            continue
        artifacts.append(ArtifactIn(filename=rel, content=content, kind=kind))
        if len(artifacts) >= MAX_FILES:
            break
    return artifacts


def _extract_zip(raw: bytes) -> List[ArtifactIn]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "That file is not a valid ZIP archive")

    with tempfile.TemporaryDirectory(prefix="apisentinel-zip-") as tmp:
        root = Path(tmp)
        for member in archive.infolist():
            if member.is_dir():
                continue
            # Zip-slip guard: resolve the destination and require it to stay inside root.
            target = (root / member.filename).resolve()
            if not str(target).startswith(str(root.resolve()) + os.sep):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "The archive contains an entry that escapes its own directory and was rejected.",
                )
            if member.file_size > settings.max_upload_bytes:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, length=64 * 1024)
        return _collect_tree(root)


def _persist_artifacts(db: Session, project: Project, artifacts: List[ArtifactIn]) -> None:
    for artifact in artifacts:
        if artifact.kind == "openapi" and not project.openapi_spec:
            project.openapi_spec = artifact.content
        db.add(
            CodeArtifact(
                project_id=project.id,
                filename=artifact.filename,
                kind=artifact.kind,
                content=artifact.content,
            )
        )


def _validate_scan_mode(scan_mode: str, runtime_base_url: str | None) -> None:
    if scan_mode in {"url", "hybrid"} and not (runtime_base_url or "").strip():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"scan_mode='{scan_mode}' needs a target URL (runtime_base_url) to scan.",
        )


@router.post("", response_model=ProjectDetail, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    _validate_scan_mode(payload.scan_mode, payload.runtime_base_url)

    project = Project(
        owner_id=user.id,
        name=payload.name,
        description=payload.description,
        business_rules=payload.business_rules,
        openapi_spec=payload.openapi_spec,
        runtime_base_url=payload.runtime_base_url,
        runtime_credentials=payload.runtime_credentials,
        scan_mode=payload.scan_mode,
        scope_config=payload.scope_config.model_dump(exclude_none=True) if payload.scope_config else None,
        # A token is always generated, even for a source-mode project, so
        # switching to url/hybrid mode later never needs a separate step to
        # become eligible for the stronger, well-known-token verification path.
        authorization_token=secrets.token_hex(24),
    )
    if payload.target_authorized:
        project.target_authorized = True
        project.authorization_method = "manual"
        project.authorization_confirmed_at = datetime.now(timezone.utc)
    db.add(project)
    db.flush()
    _persist_artifacts(db, project, payload.artifacts)
    db.commit()
    db.refresh(project)
    if project.artifacts:
        reparse_project(db, project)
        db.refresh(project)
    return _detail(project)


@router.get("", response_model=List[ProjectOut])
def list_projects(db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = db.query(Project)
    if user.role != "admin":
        query = query.filter(Project.owner_id == user.id)
    return query.order_by(Project.created_at.desc()).all()


@router.get("/{project_id}", response_model=ProjectDetail)
def get_project(project: Project = Depends(owned_project)):
    return _detail(project)


@router.patch("/{project_id}", response_model=ProjectDetail)
def update_project(
    payload: ProjectUpdate,
    project: Project = Depends(owned_project),
    db: Session = Depends(get_db),
):
    updates = payload.model_dump(exclude_unset=True)
    effective_mode = updates.get("scan_mode", project.scan_mode)
    effective_url = updates.get("runtime_base_url", project.runtime_base_url)
    _validate_scan_mode(effective_mode, effective_url)

    for field, value in updates.items():
        setattr(project, field, value)
    db.add(project)
    db.commit()
    db.refresh(project)
    return _detail(project)


class AuthorizationConfirm(BaseModel):
    confirm: bool
    statement: str = ""


class AuthorizationStatus(BaseModel):
    target_authorized: bool
    authorization_method: str | None
    authorization_confirmed_at: datetime | None


@router.post("/{project_id}/authorization/confirm", response_model=AuthorizationStatus)
def confirm_authorization(
    payload: AuthorizationConfirm,
    project: Project = Depends(owned_project),
    db: Session = Depends(get_db),
):
    """Record the project owner's explicit statement that they are authorized
    to test ``project.runtime_base_url``.

    This is the default, always-available path to satisfy the review's
    "target authorization" requirement: a deliberate, logged confirmation
    rather than an implicit default. It is a legal/organisational control, not
    a technical one — ``assert_target_allowed`` still independently requires
    the operator to have ``ALLOW_PUBLIC_TARGETS=true`` before this flag has
    any effect on a non-allowlisted public host. For a technical check instead
    of (or in addition to) a statement, see ``/authorization/verify``.
    """
    if not payload.confirm:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "confirm must be true to authorize a target.")
    project.target_authorized = True
    project.authorization_method = "manual"
    project.authorization_confirmed_at = datetime.now(timezone.utc)
    db.add(project)
    db.commit()
    db.refresh(project)
    return AuthorizationStatus(
        target_authorized=project.target_authorized,
        authorization_method=project.authorization_method,
        authorization_confirmed_at=project.authorization_confirmed_at,
    )


@router.post("/{project_id}/authorization/verify", response_model=AuthorizationStatus)
def verify_authorization(
    project: Project = Depends(owned_project),
    db: Session = Depends(get_db),
):
    """Stronger, optional authorization proof: check that the project's
    randomly-generated token (``ProjectDetail.authorization_token``) has been
    published at ``/.well-known/apisentinel-authorization.txt`` on the target,
    the way a site verifies ownership for other security tooling. Only
    confirms authorization on an exact, case-sensitive match; any other
    outcome leaves the current authorization state unchanged.
    """
    if not project.runtime_base_url:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Set a target URL on this project first.")
    try:
        target = assert_target_allowed(project.runtime_base_url, allow_public=True)
    except TargetNotAllowed as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc))

    verification_url = target.rstrip("/") + "/.well-known/apisentinel-authorization.txt"
    try:
        response = httpx.get(verification_url, timeout=10, follow_redirects=False)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"Could not fetch {verification_url}: {exc}"
        )
    if response.status_code != 200 or response.text.strip() != project.authorization_token:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{verification_url} did not contain the expected token. "
            "Publish the exact token shown for this project at that exact path and try again.",
        )

    project.target_authorized = True
    project.authorization_method = "well-known-token"
    project.authorization_confirmed_at = datetime.now(timezone.utc)
    db.add(project)
    db.commit()
    db.refresh(project)
    return AuthorizationStatus(
        target_authorized=project.target_authorized,
        authorization_method=project.authorization_method,
        authorization_confirmed_at=project.authorization_confirmed_at,
    )


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project: Project = Depends(owned_project), db: Session = Depends(get_db)):
    db.delete(project)
    db.commit()
    return None


@router.post("/{project_id}/artifacts", response_model=ProjectDetail)
async def upload_artifacts(
    files: List[UploadFile] = File(...),
    project: Project = Depends(owned_project),
    db: Session = Depends(get_db),
):
    """Accept individual source files or a ZIP archive of a project tree."""
    collected: List[ArtifactIn] = []
    total = 0
    for upload in files:
        raw = await upload.read()
        total += len(raw)
        if total > settings.max_upload_bytes:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"Upload exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB limit",
            )
        name = upload.filename or "upload"
        if name.lower().endswith(".zip"):
            collected.extend(_extract_zip(raw))
            continue
        kind = _classify(name)
        if kind is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"'{name}' is not a Python source file or an OpenAPI specification.",
            )
        collected.append(
            ArtifactIn(filename=Path(name).name, content=_decode(raw, name), kind=kind)
        )

    if not collected:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "No analysable Python source files were found in the upload.",
        )

    _persist_artifacts(db, project, collected)
    db.commit()
    db.refresh(project)
    reparse_project(db, project)
    db.refresh(project)
    return _detail(project)


@router.post("/{project_id}/artifacts/text", response_model=ProjectDetail)
def add_source_text(
    artifact: ArtifactIn,
    project: Project = Depends(owned_project),
    db: Session = Depends(get_db),
):
    """Paste a single source file — the fastest path to a first scan."""
    _persist_artifacts(db, project, [artifact])
    db.commit()
    db.refresh(project)
    reparse_project(db, project)
    db.refresh(project)
    return _detail(project)


@router.post("/{project_id}/artifacts/git", response_model=ProjectDetail)
def import_from_git(
    repo_url: str = Form(..., max_length=500),
    branch: str = Form("", max_length=200),
    project: Project = Depends(owned_project),
    db: Session = Depends(get_db),
):
    """Shallow-clone a public repository and ingest its Python sources.

    The clone is read-only input: nothing from the repository is executed, and
    submodules and credential prompts are disabled so a hostile URL cannot pull
    extra content or block the request waiting for input.
    """
    if not repo_url.startswith(("https://", "http://")):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Only http(s) repository URLs are supported"
        )

    with tempfile.TemporaryDirectory(prefix="apisentinel-git-") as tmp:
        command = ["git", "clone", "--depth", "1", "--no-tags", "--recurse-submodules=no"]
        if branch.strip():
            command += ["--branch", branch.strip()]
        command += [repo_url, tmp]
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                command,
                capture_output=True,
                text=True,
                timeout=120,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"},
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, "Cloning the repository timed out")
        if completed.returncode != 0:
            logger.warning("git clone failed: %s", completed.stderr[-500:])
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "The repository could not be cloned. Check the URL and that it is public.",
            )
        artifacts = _collect_tree(Path(tmp))

    if not artifacts:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "No Python source files were found in that repository.",
        )

    _persist_artifacts(db, project, artifacts)
    db.commit()
    db.refresh(project)
    reparse_project(db, project)
    db.refresh(project)
    return _detail(project)


@router.delete("/{project_id}/artifacts/{artifact_id}", response_model=ProjectDetail)
def delete_artifact(
    artifact_id: str,
    project: Project = Depends(owned_project),
    db: Session = Depends(get_db),
):
    artifact = next((a for a in project.artifacts if str(a.id) == artifact_id), None)
    if artifact is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    db.delete(artifact)
    db.commit()
    db.refresh(project)
    reparse_project(db, project)
    db.refresh(project)
    return _detail(project)


@router.get("/{project_id}/endpoints", response_model=List[EndpointOut])
def list_endpoints(project: Project = Depends(owned_project)):
    return sorted(project.endpoints, key=lambda e: (e.path, e.method))


def _detail(project: Project) -> ProjectDetail:
    detail = ProjectDetail.model_validate(project)
    detail.endpoints = sorted(detail.endpoints, key=lambda e: (e.path, e.method))
    return detail
