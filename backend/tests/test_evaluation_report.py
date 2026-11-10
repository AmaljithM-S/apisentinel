"""Produces a real, reproducible detection-accuracy report for both scan
modes, reusing the exact scoring logic in ``evaluation/evaluate.py`` (imported
directly, not reimplemented) against the exact ground truth it already uses.

This exists because the review asked for "a test report covering detection
accuracy, false positives, false negatives, scan limitations" — and because
Althunayyan et al. (2022) and Alazmi & De Leon (2022) both make the point that
a scanner's claims should be checked against a labelled target rather than
taken on faith. Numbers are written to
``evaluation/results/mode_comparison.md`` so they are easy to find and re-run
(``pytest tests/test_evaluation_report.py -s``), rather than only asserted on
inside a test.

Requires a real Postgres DATABASE_URL for the url-mode pipeline's endpoint
persistence helpers it shares with scan_service (though this file drives the
layer functions directly rather than going through the HTTP API, to keep the
run fast); skipped automatically on SQLite for the same reason as the other
DB-adjacent test files.
"""

from __future__ import annotations

import importlib.util
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

if "sqlite" in os.environ.get("DATABASE_URL", "sqlite://"):
    pytest.skip("requires a real Postgres DATABASE_URL", allow_module_level=True)

# evaluation/evaluate.py is a script, not an installed package — import it by
# path so its load_truth()/metrics() are reused exactly, not reimplemented.
_spec = importlib.util.spec_from_file_location("evaluate", REPO_ROOT / "evaluation" / "evaluate.py")
_evaluate = importlib.util.module_from_spec(_spec)
sys.modules["evaluate"] = _evaluate
_spec.loader.exec_module(_evaluate)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def vulnapi_server(tmp_path_factory):
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    from app.config import settings

    previous = settings.runtime_target_allowlist
    settings.runtime_target_allowlist = f"{previous},127.0.0.1:{port}"

    db_path = tmp_path_factory.mktemp("vulnapi") / "vulnapi.db"
    env = dict(os.environ)
    env["VULNAPI_DB"] = str(db_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "targets.vulnapi.app:app", "--app-dir", str(REPO_ROOT),
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(REPO_ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 15
        up = False
        while time.monotonic() < deadline:
            try:
                httpx.get(f"{base_url}/openapi.json", timeout=1)
                up = True
                break
            except httpx.HTTPError:
                time.sleep(0.25)
        if not up:
            proc.kill()
            pytest.skip("Could not start the bundled vulnapi target.")
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        settings.runtime_target_allowlist = previous


CREDENTIALS = {
    "login_path": "/login",
    "login_style": "json",
    "identifier_field": "email",
    "token_field": "access_token",
    "users": [
        {"label": "alice", "email": "alice@vulnshop.test", "password": "alice-password", "object_id": "1001"},
        {"label": "bob", "email": "bob@vulnshop.test", "password": "bob-password", "object_id": "1002"},
    ],
}


def _flagged_pairs(fused):
    """Mirror evaluate.py's scoring rule exactly: a runtime-refuted finding
    does not count as flagged, the same way an analyst reading the dashboard
    would discount it."""
    out = set()
    for f in fused:
        if f.runtime_refuted:
            continue
        if not f.endpoint_key:
            continue
        method, _, path = f.endpoint_key.partition(" ")
        out.add((method, path, f.category))
    return out


def _run_source_mode():
    from app.parser.fastapi_parser import parse_source_files
    from app.static_layer import run_static_layer

    source = (REPO_ROOT / "targets" / "vulnapi" / "app.py").read_text("utf-8")
    endpoints, _warnings = parse_source_files([("app.py", source)])
    static_result = run_static_layer([("app.py", source)], endpoints)
    all_findings = list(static_result.findings)
    return endpoints, all_findings


def _run_url_mode(target_url: str):
    from app.static_layer import run_static_layer
    from app.web_layer import run_web_discovery

    discovery = run_web_discovery(target_url, scope_config={"max_pages": 40, "run_active_probes": True})
    static_result = run_static_layer([], discovery.endpoints)
    all_findings = list(discovery.layer_result.findings) + list(static_result.findings)
    return discovery.endpoints, all_findings


@pytest.mark.parametrize("mode", ["source", "url"])
def test_detection_accuracy_report(vulnapi_server, mode, tmp_path):
    from app.risk_engine import fuse_findings
    from app.runtime_layer import run_runtime_layer

    if mode == "source":
        endpoints, all_findings = _run_source_mode()
    else:
        endpoints, all_findings = _run_url_mode(vulnapi_server)

    runtime_result = run_runtime_layer(vulnapi_server, CREDENTIALS, all_findings, use_zap=False)
    all_findings += runtime_result.findings
    fused = fuse_findings(all_findings)

    positives, negatives = _evaluate.load_truth()
    flagged = _flagged_pairs(fused)
    scores = _evaluate.metrics(flagged, positives, negatives)

    results_dir = REPO_ROOT / "evaluation" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    report_path = results_dir / "mode_comparison.md"
    existing = report_path.read_text() if report_path.exists() else (
        "# Detection accuracy: source mode vs URL mode\n\n"
        "Generated by `pytest backend/tests/test_evaluation_report.py -s`. Scored against "
        "`datasets/ground_truth.yml` using the exact scoring rule in `evaluation/evaluate.py` "
        "(a runtime-refuted finding does not count as flagged). Single run, not averaged over "
        "multiple runs like `evaluate.py --runs N`, so treat these as one real data point, not "
        "a statistically stable estimate.\n\n"
        "| Mode | Endpoints found | TP | FP | FN | TN | Precision | Recall | F1 |\n"
        "|---|---|---|---|---|---|---|---|---|\n"
    )
    row = (
        f"| {mode} | {len(endpoints)} | {scores['tp']:.0f} | {scores['fp']:.0f} | {scores['fn']:.0f} | "
        f"{scores['tn']:.0f} | {scores['precision']:.2f} | {scores['recall']:.2f} | {scores['f1']:.2f} |\n"
    )
    if row not in existing:
        existing += row
    report_path.write_text(existing)

    print(f"\n[{mode}-mode] endpoints={len(endpoints)} {scores}")

    # Regression guard, not a quality bar: a working pipeline must find *some*
    # true positives on a target this deliberately vulnerable, in both modes.
    assert scores["tp"] >= 1, f"{mode}-mode found zero true positives — something regressed"
