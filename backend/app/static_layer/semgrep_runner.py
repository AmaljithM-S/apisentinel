"""Semgrep integration with an API-security specific rule pack.

Semgrep runs offline against the bundled rule pack (``rules/apisentinel.yml``)
so scans need no network access and produce identical results on every machine
— a requirement of the reproducible evaluation methodology.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import List

from app.analysis_types import LayerFinding, LayerResult
from app.config import settings
from app.owasp import normalise_category

RULES_PATH = Path(__file__).parent / "rules" / "apisentinel.yml"

_SEVERITY = {"INFO": "low", "WARNING": "medium", "ERROR": "high"}


def run_semgrep(source_dir: Path) -> LayerResult:
    started = time.monotonic()
    result = LayerResult()
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [
                "semgrep",
                "scan",
                "--config",
                str(RULES_PATH),
                "--json",
                "--quiet",
                "--no-git-ignore",
                "--metrics",
                "off",
                "--disable-version-check",
                str(source_dir),
            ],
            capture_output=True,
            text=True,
            timeout=settings.static_timeout_seconds,
            check=False,
        )
    except FileNotFoundError:
        result.ok = False
        result.warnings.append("Semgrep is not installed in this environment.")
        return result
    except subprocess.TimeoutExpired:
        result.ok = False
        result.warnings.append(
            f"Semgrep timed out after {settings.static_timeout_seconds}s and was stopped."
        )
        return result

    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        result.ok = False
        result.warnings.append(
            "Semgrep produced no parsable JSON output: " + (completed.stderr or "")[:300]
        )
        return result

    findings: List[LayerFinding] = []
    for item in payload.get("results", []):
        extra = item.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        category = normalise_category(meta.get("owasp_api") or item.get("check_id"))
        severity = _SEVERITY.get(str(extra.get("severity", "WARNING")).upper(), "medium")
        findings.append(
            LayerFinding(
                source="static",
                tool="semgrep",
                category=category,
                title=str(meta.get("title") or item.get("check_id", "semgrep finding"))[:280],
                description=str(extra.get("message", "")).strip(),
                severity=str(meta.get("severity") or severity),
                # Report-defined indicative confidence for a Semgrep pattern match.
                confidence=0.70,
                source_file=_relative(item.get("path", ""), source_dir),
                line_start=(item.get("start") or {}).get("line"),
                detail={
                    "check_id": item.get("check_id"),
                    "cwe": meta.get("cwe"),
                    "lines": extra.get("lines"),
                },
                remediation_hint=meta.get("remediation"),
            )
        )

    for error in payload.get("errors", [])[:5]:
        result.warnings.append(f"semgrep: {str(error.get('message', error))[:200]}")

    result.findings = findings
    result.duration_seconds = time.monotonic() - started
    return result


def _relative(path: str, root: Path) -> str:
    try:
        return str(Path(path).relative_to(root))
    except (ValueError, TypeError):
        return path
