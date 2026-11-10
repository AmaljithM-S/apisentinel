"""Static analysis layer orchestration.

Writes the uploaded artifacts to a throwaway directory, runs Bandit and Semgrep
against it as real subprocesses, adds deterministic structural analysis of the
parsed endpoints, and attributes every tool finding back to the endpoint whose
line range contains it — which is what lets the risk engine fuse a Semgrep hit
with an LLM judgement about the same endpoint.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional, Sequence

from app.analysis_types import LayerFinding, LayerResult
from app.config import settings
from app.parser.fastapi_parser import ParsedEndpoint
from app.static_layer.bandit_runner import run_bandit
from app.static_layer.semgrep_runner import run_semgrep
from app.static_layer.structural import analyse_endpoints, merge_results


def _materialise(files: Sequence[tuple[str, str]], root: Path) -> None:
    for filename, content in files:
        safe = filename.replace("\\", "/").lstrip("/")
        if ".." in safe.split("/"):
            continue
        target = root / safe
        target.parent.mkdir(parents=True, exist_ok=True)
        if len(content.encode("utf-8")) > settings.max_upload_bytes:
            content = content[: settings.max_upload_bytes]
        target.write_text(content, encoding="utf-8")


def _attribute(
    finding: LayerFinding, endpoints: Sequence[ParsedEndpoint]
) -> Optional[ParsedEndpoint]:
    if finding.endpoint_key:
        for endpoint in endpoints:
            if endpoint.key == finding.endpoint_key:
                return endpoint
        return None
    if not finding.source_file or not finding.line_start:
        return None
    for endpoint in endpoints:
        if endpoint.source_file.endswith(finding.source_file) or finding.source_file.endswith(
            endpoint.source_file
        ):
            if endpoint.line_start <= finding.line_start <= endpoint.line_end:
                return endpoint
    return None


def run_static_layer(
    files: Sequence[tuple[str, str]], endpoints: Sequence[ParsedEndpoint]
) -> LayerResult:
    with tempfile.TemporaryDirectory(prefix="apisentinel-static-") as tmp:
        root = Path(tmp)
        _materialise(files, root)
        bandit_result = run_bandit(root)
        semgrep_result = run_semgrep(root)

    structural_result = analyse_endpoints(endpoints)
    merged = merge_results([bandit_result, semgrep_result, structural_result])

    for finding in merged.findings:
        endpoint = _attribute(finding, endpoints)
        if endpoint is not None:
            finding.endpoint_key = endpoint.key
    merged.detail["tools"] = {
        "bandit": {"ok": bandit_result.ok, "findings": len(bandit_result.findings)},
        "semgrep": {"ok": semgrep_result.ok, "findings": len(semgrep_result.findings)},
        "structural": {"ok": True, "findings": len(structural_result.findings)},
    }
    return merged
