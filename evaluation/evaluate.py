"""APISentinel evaluation harness.

Runs the hybrid pipeline against the bundled vulnerable target N times, scores
it against datasets/ground_truth.yml, and compares it with single-layer
baselines (static-only = Bandit+Semgrep+structural, LLM-only, runtime-only/ZAP).

Scoring unit: (endpoint, OWASP category) pairs.
  TP  flagged pair that is in the endpoint's labels
  FP  flagged pair not in the labels (incl. anything on a negative control)
  FN  labelled pair never flagged
  TN  negative-control endpoint with nothing flagged
Findings demoted by runtime refutation ("[refuted at runtime]") count as not
flagged, exactly as an analyst would read the report.

Usage (inside the backend container, see `make evaluate`):
    python /evaluation/evaluate.py --runs 3
Outputs: evaluation/results/metrics.csv and evaluation/results/report.md
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple

import httpx
import yaml

HERE = Path(__file__).resolve().parent
API = os.environ.get("APISENTINEL_API", "http://localhost:8000")
EMAIL = os.environ.get("DEMO_USER_EMAIL", "analyst@apisentinel.local")
PASSWORD = os.environ.get("DEMO_USER_PASSWORD", "apisentinel123")
GT_PATH = Path(os.environ.get("GROUND_TRUTH_PATH", "/datasets/ground_truth.yml"))

STATIC_SOURCES = {"static"}
LLM_SOURCES = {"llm", "stride", "business_rule"}
RUNTIME_SOURCES = {"runtime"}

Pair = Tuple[str, str, str]  # method, path, category


def load_truth() -> Tuple[Set[Pair], Set[Tuple[str, str]]]:
    data = yaml.safe_load(GT_PATH.read_text())
    positives: Set[Pair] = set()
    negatives: Set[Tuple[str, str]] = set()
    for ep in data["endpoints"]:
        key = (ep["method"].upper(), ep["path"])
        if ep.get("vulnerable"):
            for label in ep.get("labels") or [ep["primary"]]:
                positives.add((*key, label))
        else:
            negatives.add(key)
    return positives, negatives


def metrics(flagged: Set[Pair], positives: Set[Pair], negatives: Set[Tuple[str, str]]) -> Dict[str, float]:
    tp = len(flagged & positives)
    fp = len(flagged - positives)
    fn = len(positives - flagged)
    flagged_eps = {(m, p) for m, p, _ in flagged}
    tn = len(negatives - flagged_eps)
    neg_fp = len(negatives & flagged_eps)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = neg_fp / (neg_fp + tn) if neg_fp + tn else 0.0
    fnr = fn / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision,
            "recall": recall, "f1": f1, "fpr": fpr, "fnr": fnr}


class Client:
    def __init__(self) -> None:
        self.http = httpx.Client(base_url=API, timeout=60)
        tok = self.http.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
        tok.raise_for_status()
        self.http.headers["Authorization"] = f"Bearer {tok.json()['access_token']}"

    def get(self, path: str):
        r = self.http.get(path)
        r.raise_for_status()
        return r.json()

    def demo_project(self, name_contains: str | None = None) -> dict:
        projects = self.get("/api/projects")
        candidates = [p for p in projects if p.get("runtime_base_url")]
        if name_contains:
            matches = [p for p in candidates if name_contains.lower() in p["name"].lower()]
            if not matches:
                sys.exit(
                    f"No project with a target URL whose name contains '{name_contains}' was found. "
                    f"Available: {[p['name'] for p in candidates]}"
                )
            return self.get(f"/api/projects/{matches[0]['id']}")
        if not candidates:
            sys.exit("No demo project found — was the backend bootstrapped with SEED_DEMO_USER=true?")
        if len(candidates) > 1:
            # Bootstrap now seeds two demo projects with a target URL (the
            # original source-mode one and a url-mode one, see
            # app.bootstrap.seed_demo_url_project) — default to the
            # source-mode one for backward compatibility with existing
            # results, and let --project-name pick the other explicitly.
            source_mode = [p for p in candidates if p.get("scan_mode", "source") == "source"]
            if source_mode:
                return self.get(f"/api/projects/{source_mode[0]['id']}")
        return self.get(f"/api/projects/{candidates[0]['id']}")

    def run_scan(self, project: dict, timeout_s: int) -> str:
        body = {"run_static": True, "run_llm": True, "run_runtime": True,
                "runtime_base_url": project["runtime_base_url"],
                "runtime_credentials": project.get("runtime_credentials")}
        if project.get("scan_mode", "source") in ("url", "hybrid"):
            # No source was uploaded to this project, so static analysis has
            # nothing of its own to run — structural checks still run against
            # the web-discovered endpoints (see services.scan_service), but
            # Bandit/Semgrep have no files either way. Kept as run_static=True
            # above since that is what makes the structural pass happen.
            body["run_active_probes"] = True
        r = self.http.post(f"/api/projects/{project['id']}/scans", json=body)
        r.raise_for_status()
        scan_id = r.json()["id"]
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            scan = self.get(f"/api/scans/{scan_id}")
            if scan["status"] not in ("queued", "running"):
                print(f"  scan {scan_id} -> {scan['status']} {scan.get('layer_status')}")
                return scan_id
            time.sleep(5)
        sys.exit(f"Scan {scan_id} did not finish within {timeout_s}s")

    def flagged_sets(self, scan_id: str) -> Dict[str, Set[Pair]]:
        out: Dict[str, Set[Pair]] = {"hybrid": set(), "static-only": set(), "llm-only": set(), "runtime/zap-only": set()}
        for f in self.get(f"/api/scans/{scan_id}/findings"):
            if not f.get("method") or not f.get("path"):
                continue
            pair = (f["method"].upper(), f["path"], f["owasp_category"])
            detail = self.get(f"/api/findings/{f['id']}")
            sources = {e["source"] for e in detail["evidence"]}
            if "[refuted at runtime]" not in f["title"]:
                out["hybrid"].add(pair)
            if sources & STATIC_SOURCES:
                out["static-only"].add(pair)
            if sources & LLM_SOURCES:
                out["llm-only"].add(pair)
            if any(t["confirmed"] for t in detail["runtime_tests"]) or (
                sources & RUNTIME_SOURCES and "[refuted at runtime]" not in f["title"]
            ):
                out["runtime/zap-only"].add(pair)
        return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--out", default=str(HERE / "results"))
    ap.add_argument(
        "--project-name",
        default=None,
        help=(
            "Substring to pick a specific project by name, e.g. 'URL scan only' to evaluate "
            "the black-box (url-mode) demo project instead of the default source-mode one."
        ),
    )
    args = ap.parse_args()

    positives, negatives = load_truth()
    print(f"Ground truth: {len(positives)} labelled (endpoint, category) pairs, {len(negatives)} negative controls")
    client = Client()
    project = client.demo_project(args.project_name)
    print(f"Evaluating project: {project['name']!r} (scan_mode={project.get('scan_mode', 'source')})")

    per_run: Dict[str, List[Dict[str, float]]] = {}
    for i in range(args.runs):
        print(f"Run {i + 1}/{args.runs}")
        sets = client.flagged_sets(client.run_scan(project, args.timeout))
        for name, flagged in sets.items():
            per_run.setdefault(name, []).append(metrics(flagged, positives, negatives))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    keys = ["precision", "recall", "f1", "fpr", "fnr"]
    with (out / "metrics.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["approach", "run", "tp", "fp", "fn", "tn", *keys])
        for name, runs in per_run.items():
            for idx, m in enumerate(runs, 1):
                w.writerow([name, idx, m["tp"], m["fp"], m["fn"], m["tn"], *(f"{m[k]:.4f}" for k in keys)])

    lines = ["# APISentinel evaluation report", "",
             f"Dataset: `{GT_PATH.name}` — {len(positives)} positive pairs, {len(negatives)} negative controls. Runs: {args.runs}.", "",
             "| Approach | Precision | Recall | F1 | FPR | FNR | F1 std-dev |", "|---|---|---|---|---|---|---|"]
    for name, runs in per_run.items():
        mean = {k: statistics.mean(r[k] for r in runs) for k in keys}
        sd = statistics.pstdev([r["f1"] for r in runs]) if len(runs) > 1 else 0.0
        lines.append(f"| {name} | {mean['precision']:.3f} | {mean['recall']:.3f} | {mean['f1']:.3f} | {mean['fpr']:.3f} | {mean['fnr']:.3f} | {sd:.3f} |")
    lines += ["", "Baselines are derived from the evidence each layer contributed in the same scans, so every approach sees identical input.",
              "A non-zero F1 std-dev reflects LLM non-determinism across repeated runs."]
    (out / "report.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
