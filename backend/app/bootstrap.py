"""Idempotent startup bootstrap: demo account, labelled dataset, demo project.

Run by the container entrypoint after migrations. Everything here is safe to run
repeatedly — it upserts rather than inserts, so restarting the stack never
duplicates data or overwrites a password the operator has changed.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml
from sqlalchemy import select

from app.config import settings
from app.db.models import CodeArtifact, GroundTruth, Project, User
from app.db.session import session_scope
from app.logging_config import configure_logging
from app.security import hash_password
from app.services.scan_service import reparse_project

logger = logging.getLogger("apisentinel.bootstrap")

VULNAPI_SOURCE = Path("/targets/vulnapi/app.py")
VULNAPI_RULES = Path("/targets/vulnapi/business_rules.md")
DEMO_PROJECT_NAME = "VulnShop API (bundled demo target)"
DEMO_URL_PROJECT_NAME = "VulnShop API — URL scan only (black-box demo)"

# Shared by both demo projects: the same bundled target, the same two test
# accounts. Defined once so the url-mode demo cannot silently drift from the
# source-mode one.
_DEMO_RUNTIME_CREDENTIALS = {
    "login_path": "/login",
    "login_style": "json",
    "token_field": "access_token",
    # vulnapi's /login endpoint expects the identifier under the JSON key
    # "email" (see targets/vulnapi/app.py: LoginIn.email), not "username" —
    # this field tells the tester which key to send, independently of what
    # each account entry is labelled.
    "identifier_field": "email",
    "users": [
        {
            "label": "low-privilege user A",
            "email": "alice@vulnshop.test",
            "password": "alice-password",
            "object_id": "1001",
            "owned_ids": ["1001", "5001"],
        },
        {
            "label": "low-privilege user B",
            "email": "bob@vulnshop.test",
            "password": "bob-password",
            "object_id": "1002",
            "owned_ids": ["1002", "5002"],
        },
    ],
}


def seed_demo_user() -> None:
    if not settings.seed_demo_user:
        return
    with session_scope() as db:
        email = settings.demo_user_email.lower()
        existing = db.scalar(select(User).where(User.email == email))
        if existing is not None:
            logger.info("demo user already present", extra={"email": email})
            return
        db.add(
            User(
                email=email,
                password_hash=hash_password(settings.demo_user_password),
                role="analyst",
            )
        )
        logger.info("created demo user", extra={"email": email})


def seed_ground_truth() -> None:
    if not settings.seed_ground_truth:
        return
    path = Path(settings.ground_truth_path)
    if not path.exists():
        logger.warning("ground truth file not found", extra={"path": str(path)})
        return

    data: Dict[str, Any] = yaml.safe_load(path.read_text("utf-8")) or {}
    dataset = str(data.get("dataset", "custom-fastapi"))
    entries: List[Dict[str, Any]] = data.get("endpoints") or []

    with session_scope() as db:
        for entry in entries:
            method = str(entry["method"]).upper()
            route = str(entry["path"])
            row = db.scalar(
                select(GroundTruth).where(
                    GroundTruth.dataset == dataset,
                    GroundTruth.method == method,
                    GroundTruth.path == route,
                )
            )
            if row is None:
                row = GroundTruth(dataset=dataset, method=method, path=route)
                db.add(row)
            row.vulnerable = bool(entry.get("vulnerable"))
            row.owasp_category = entry.get("primary") or None
            row.business_rule = entry.get("business_rule")
            row.notes = entry.get("notes")
        logger.info("ground truth seeded", extra={"dataset": dataset, "endpoints": len(entries)})


def seed_demo_project() -> None:
    """Give the demo account a project that is ready to scan on first login."""
    if not settings.seed_demo_user or not VULNAPI_SOURCE.exists():
        return

    with session_scope() as db:
        user = db.scalar(select(User).where(User.email == settings.demo_user_email.lower()))
        if user is None:
            return
        existing = db.scalar(
            select(Project).where(
                Project.owner_id == user.id, Project.name == DEMO_PROJECT_NAME
            )
        )
        if existing is not None:
            logger.info("demo project already present")
            return

        project = Project(
            owner_id=user.id,
            name=DEMO_PROJECT_NAME,
            description=(
                "The deliberately vulnerable service bundled with this stack. Its source is "
                "already loaded and its documented business rules are attached, so a scan can "
                "be run immediately. Runtime validation is pre-pointed at the running container."
            ),
            business_rules=VULNAPI_RULES.read_text("utf-8") if VULNAPI_RULES.exists() else None,
            runtime_base_url="http://vulnapi:8001",
            runtime_credentials=_DEMO_RUNTIME_CREDENTIALS,
            scan_mode="source",
        )
        db.add(project)
        db.flush()
        db.add(
            CodeArtifact(
                project_id=project.id,
                filename="vulnapi/app.py",
                kind="source",
                content=VULNAPI_SOURCE.read_text("utf-8"),
            )
        )
        db.flush()
        db.refresh(project)
        reparse_project(db, project)
        logger.info("demo project created", extra={"project": DEMO_PROJECT_NAME})


def seed_demo_url_project() -> None:
    """A second demo project, scanned by URL only — no source, no SQL script —
    against the exact same bundled target, to make URL-based scanning
    demonstrable the moment the stack starts.

    Runtime validation is enabled by default here (unlike the source-mode demo
    project, where it is an opt-in toggle on the scan), since confirming a
    finding at runtime is the main evidence a black-box scan can offer without
    source code to read.
    """
    if not settings.seed_demo_user:
        return

    with session_scope() as db:
        user = db.scalar(select(User).where(User.email == settings.demo_user_email.lower()))
        if user is None:
            return
        existing = db.scalar(
            select(Project).where(
                Project.owner_id == user.id, Project.name == DEMO_URL_PROJECT_NAME
            )
        )
        if existing is not None:
            logger.info("demo url-mode project already present")
            return

        project = Project(
            owner_id=user.id,
            name=DEMO_URL_PROJECT_NAME,
            description=(
                "The same bundled vulnerable service as the other demo project, scanned here "
                "purely by URL: no source code or SQL script is uploaded. Endpoints are "
                "discovered from its live OpenAPI document and by crawling it, the same way a "
                "scan of someone else's authorized website would work. Already marked "
                "authorized because this is the project's own bundled, Docker-internal target."
            ),
            business_rules=VULNAPI_RULES.read_text("utf-8") if VULNAPI_RULES.exists() else None,
            runtime_base_url="http://vulnapi:8001",
            runtime_credentials=_DEMO_RUNTIME_CREDENTIALS,
            scan_mode="url",
            # Safe to pre-authorize: this is the project's own bundled target,
            # already reachable only because it is on RUNTIME_TARGET_ALLOWLIST
            # (a Docker-internal hostname, not a public site) — the same trust
            # boundary as the source-mode demo project above, not a new one.
            target_authorized=True,
            authorization_method="manual",
            authorization_confirmed_at=datetime.now(timezone.utc),
        )
        db.add(project)
        db.commit()
        logger.info("demo url-mode project created", extra={"project": DEMO_URL_PROJECT_NAME})


def main() -> int:
    configure_logging()
    try:
        seed_demo_user()
        seed_ground_truth()
        seed_demo_project()
        seed_demo_url_project()
    except Exception:  # noqa: BLE001 - bootstrap must not block the API from starting
        logger.exception("bootstrap failed; the API will still start")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
