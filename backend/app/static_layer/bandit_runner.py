"""Bandit integration.

Bandit is executed as a real subprocess against a temporary copy of the
uploaded source, with a wall-clock timeout and JSON output. Running the actual
tool (instead of reimplementing its rules) is what makes the framework's
results directly comparable with the standalone Bandit baseline used in the
evaluation chapter.
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

_SEVERITY = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}

# Bandit test ids mapped onto the OWASP API taxonomy. Unlisted ids fall back to
# API8 (security misconfiguration), which is the correct default for the
# hygiene-style checks that make up most of Bandit's rule set.
_TEST_CATEGORY = {
    "B608": "API10",  # hardcoded_sql_expressions
    "B602": "API10",  # subprocess with shell=True
    "B603": "API10",
    "B605": "API10",
    "B609": "API10",
    "B307": "API10",  # eval
    "B105": "API2",  # hardcoded_password_string
    "B106": "API2",
    "B107": "API2",
    "B201": "API8",  # flask debug=True
    "B104": "API8",  # bind all interfaces
    "B501": "API8",  # requests without cert verification
    "B303": "API8",  # insecure hash
    "B324": "API8",
}


def run_bandit(source_dir: Path) -> LayerResult:
    started = time.monotonic()
    result = LayerResult()
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["bandit", "-r", str(source_dir), "-f", "json", "-q", "--exit-zero"],
            capture_output=True,
            text=True,
            timeout=settings.static_timeout_seconds,
            check=False,
        )
    except FileNotFoundError:
        result.ok = False
        result.warnings.append("Bandit is not installed in this environment.")
        return result
    except subprocess.TimeoutExpired:
        result.ok = False
        result.warnings.append(
            f"Bandit timed out after {settings.static_timeout_seconds}s and was stopped."
        )
        return result

    payload = _load_json(completed.stdout)
    if payload is None:
        result.ok = False
        result.warnings.append(
            "Bandit produced no parsable JSON output: " + (completed.stderr or "")[:300]
        )
        return result

    findings: List[LayerFinding] = []
    for item in payload.get("results", []):
        test_id = str(item.get("test_id", ""))
        category = _TEST_CATEGORY.get(test_id, normalise_category(item.get("test_name")))
        severity = _SEVERITY.get(str(item.get("issue_severity", "MEDIUM")).upper(), "medium")
        rel = _relative(item.get("filename", ""), source_dir)
        findings.append(
            LayerFinding(
                source="static",
                tool="bandit",
                category=category,
                title=f"{item.get('test_name', test_id)}: {item.get('issue_text', '')[:180]}",
                description=str(item.get("issue_text", "")),
                severity=severity,
                # Report-defined indicative confidence for a Bandit pattern match.
                confidence=0.65,
                source_file=rel,
                line_start=item.get("line_number"),
                detail={
                    "test_id": test_id,
                    "bandit_confidence": item.get("issue_confidence"),
                    "code": item.get("code"),
                    "more_info": item.get("more_info"),
                },
            )
        )

    result.findings = findings
    result.duration_seconds = time.monotonic() - started
    result.detail = {"metrics": payload.get("metrics", {}).get("_totals", {})}
    return result


def _load_json(raw: str):
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Bandit occasionally prefixes warnings; recover the JSON object.
        start = raw.find("{")
        if start == -1:
            return None
        try:
            return json.loads(raw[start:])
        except json.JSONDecodeError:
            return None


def _relative(path: str, root: Path) -> str:
    try:
        return str(Path(path).relative_to(root))
    except (ValueError, TypeError):
        return path
