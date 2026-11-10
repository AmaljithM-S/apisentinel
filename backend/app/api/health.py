"""Health and capability reporting.

The dashboard uses this to tell the analyst *before* a scan which layers are
actually available, instead of letting them discover a missing model or an
unreachable ZAP only in the results.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.db.session import get_db
from app.llm_layer import get_provider
from app.owasp import CATEGORIES
from app.runtime_layer.zap_client import ZapClient
from app.schemas import HealthResponse

router = APIRouter(prefix="/api", tags=["system"])
VERSION = "1.0.0"


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        database = True
    except Exception:  # noqa: BLE001 - health must report, never raise
        database = False

    llm_reachable = None
    if settings.llm_enabled:
        try:
            llm_reachable = get_provider().available()
        except Exception:  # noqa: BLE001
            llm_reachable = False

    return HealthResponse(
        status="ok" if database else "degraded",
        database=database,
        llm_provider=settings.llm_provider,
        llm_reachable=llm_reachable,
        zap_configured=ZapClient().configured,
        version=VERSION,
    )


@router.get("/taxonomy")
def taxonomy():
    """The OWASP API Top 10 taxonomy the UI renders filters and badges from."""
    return {
        key: {
            "id": key,
            "title": meta.title,
            "cwe": meta.cwe,
            "stride": meta.stride,
            "description": meta.description,
            "base_severity": meta.base_severity,
        }
        for key, meta in CATEGORIES.items()
    }


@router.get("/capabilities")
def capabilities():
    zap = ZapClient()
    return {
        "static": {"tools": ["bandit", "semgrep", "structural"], "available": True},
        "llm": {
            "enabled": settings.llm_enabled,
            "provider": settings.llm_provider,
            "model": (
                settings.ollama_model
                if settings.llm_provider == "ollama"
                else settings.hosted_llm_model
            ),
        },
        "runtime": {
            "allowlist": settings.allowlisted_targets,
            "zap_configured": zap.configured,
        },
    }
