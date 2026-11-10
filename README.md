# APISentinel — Hybrid Multi-Layer API Security Framework

APISentinel finds OWASP API Top 10 (2023) vulnerabilities in FastAPI services. It runs five layers and combines their results into one risk model:

1. **Parser**: reads the code's structure to find FastAPI routes, router prefixes, auth dependencies and path parameters, and matches them against an OpenAPI spec. Uploaded code is only read, never executed.
2. **Static analysis**: real Bandit and Semgrep (with a custom API rule pack), plus structural BOLA/BFLA/auth checks.
3. **AI reasoning**: a 4-step LLM pipeline (Purpose → Expected Controls → Verification → Classification), a check against your documented business rules, and STRIDE threat tagging. You can plug in **Ollama** (default: offline and free) or any OpenAI-compatible hosted API.
4. **Runtime validation**: differential authorization tests (BOLA, missing auth, sensitive fields) with httpx, plus OWASP ZAP passive scanning. It only probes targets on the allowlist.
5. **Risk engine**: combines evidence from independent layers with noisy-OR. A runtime confirmation pins confidence at 0.95–0.98. A runtime refutation demotes the finding. Single-layer AI suspicions are capped and flagged for manual review.

A project can be scanned two ways:
- **Source mode** (above): upload code, an OpenAPI spec, or import a Git repo.
- **URL mode**: scan a live, authorized target by **URL alone** — no source code or SQL script needed. Endpoints are discovered from the target's own OpenAPI document and by crawling it; every layer above still runs, including runtime validation. Two opt-in extras are also built in: rendering pages in a real headless browser to catch links/forms/API calls that only exist after JavaScript runs (single-page apps), and OWASP ZAP's Active Scan for a real attack-payload sweep (gated behind two independent switches, since it is genuinely intrusive). See **[docs/WEB_SCANNING.md](docs/WEB_SCANNING.md)** for the architecture, the authorization/SSRF model, and real precision/recall numbers for each mode.
- **Hybrid**: both, merged.

## Quick start (one command)

Requirements: Docker + Docker Compose v2.

```bash
cp .env.example .env      # optional — `make up` does this for you
make up                   # or: docker compose up -d --build
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:3000 |
| API + Swagger | http://localhost:8000/docs |
| Vulnerable demo target | http://localhost:8001 (do **not** expose publicly) |
| OWASP ZAP | http://localhost:8090 |

Sign in with **analyst@apisentinel.local / apisentinel123**. Two demo projects are already set up against the same bundled vulnerable target, so both modes are demonstrable immediately:
- **"VulnShop API (bundled demo target)"** — source mode: code, business rules and runtime credentials already loaded. Open it, tick all three layers, and click **Start scan**.
- **"VulnShop API — URL scan only (black-box demo)"** — URL mode: no source uploaded, already marked authorized (it's the project's own bundled, allowlisted target). Open it and click **Start scan** to see the same target found and tested purely from its URL. See [docs/WEB_SCANNING.md](docs/WEB_SCANNING.md).

### LLM setup
- **Ollama (default):** install Ollama on the host, then run `ollama pull qwen2.5-coder:7b`. The backend reaches it at `host.docker.internal:11434`.
- **Hosted:** set `LLM_PROVIDER=hosted`, `HOSTED_LLM_BASE_URL` (OpenAI-compatible `/v1`), `HOSTED_LLM_API_KEY` and `HOSTED_LLM_MODEL` in `.env`.
- **None:** `LLM_PROVIDER=disabled`. The other layers still run, and the scan shows the AI layer as *skipped*.

## Evaluation harness

```bash
make evaluate            # RUNS=5 make evaluate for more repetitions — source-mode demo project
make evaluate-url        # the same, against the URL-only (black-box) demo project
```
This scans a demo target repeatedly and scores the results against `datasets/ground_truth.yml` (which includes negative controls). It reports precision, recall, F1, FPR and FNR for **hybrid** and for **static-only (Bandit/Semgrep)**, **LLM-only** and **runtime/ZAP-only** baselines, plus F1 variance across runs. Results are written to `evaluation/results/metrics.csv` and `report.md`. For a one-shot comparison of both modes together, see `evaluation/results/mode_comparison.md` and [docs/WEB_SCANNING.md §7](docs/WEB_SCANNING.md#7-testing-and-evaluation).

## Using it on your own API

**By URL (no source needed):** create a project with scan mode "Website URL", set the target, confirm authorization (a statement, or publish the shown token at `/.well-known/apisentinel-authorization.txt` on the target for automatic verification), and start a scan. Full detail, including the SSRF/authorization model: [docs/WEB_SCANNING.md](docs/WEB_SCANNING.md).

**By source:**
1. Create a project and add business rules (one per line).
2. Add code: paste it, upload `.py`/OpenAPI files or a `.zip`, or import a public Git repo.
3. To use runtime validation, add your target's base URL to `RUNTIME_TARGET_ALLOWLIST` (or, for a public target, see URL-mode authorization above — the same `assert_target_allowed` gate covers both). Then supply test credentials as JSON, e.g. `{"identifier_field": "email", "users":[{"email":"alice@example.com","password":"..."},{"email":"bob@example.com","password":"..."}]}`. `identifier_field` names the JSON key your login endpoint expects (defaults to `"username"`); it must match, or authentication silently fails and runtime validation reports nothing. Use the same format as the demo project.
4. Review findings: each one is labelled **confirmed**, **suspected** or **inconclusive** based on whether runtime validation proved it; mark it confirmed, false positive or fixed, or re-verify it at runtime. Export reports as JSON, Markdown or SARIF (for GitHub code scanning).

## Tests & CI
```bash
make test                 # pytest (backend) + Vitest/Testing Library (dashboard)
```
`.github/workflows/ci.yml` runs the backend tests against SQLite (fast) and again against a real Postgres service container (covers the URL-mode integration tests, which need real JSONB/UUID columns), the dashboard tests and build, a Semgrep self-scan with SARIF upload, and a Docker build check.

## Production checklist
- Set a strong `JWT_SECRET` and `ENVIRONMENT=production`. This also turns off the API docs.
- Restrict `CORS_ORIGINS` to the dashboard's origin.
- Change the Postgres password and the demo account. Or set `SEED_DEMO_USER=false`.
- Never deploy `targets/vulnapi`. It is deliberately insecure.
- Keep `RUNTIME_TARGET_ALLOWLIST` limited to systems you are authorized to test.
- Leave `ALLOW_PUBLIC_TARGETS=false` unless URL-based scanning of non-allowlisted, public targets is actually needed; it is a second, independent switch from a project's own authorization record (see [docs/WEB_SCANNING.md §4](docs/WEB_SCANNING.md#4-target-authorization-scope-and-ssrf-protection)).
- Leave `ZAP_ENABLE_ACTIVE_SCAN=false` unless you specifically want ZAP's intrusive Active Scan available at all; it still needs a per-scan opt-in on top of this.

## Layout
```text
backend/      FastAPI app (parser, static_layer, llm_layer, web_layer, runtime_layer, risk_engine, remediation, api), Alembic, tests
frontend/     React + TypeScript dashboard (Vite, served by nginx)
targets/      vulnapi: deliberately vulnerable FastAPI target + business_rules.md
datasets/     ground_truth.yml answer key
evaluation/   evaluate.py harness and results/
docs/         WEB_SCANNING.md — URL-based scanning: architecture, SSRF model, methodology, research mapping, test results
```

Built-in safeguards: rate-limited auth, ownership checks on every object (the tool doesn't ship the BOLA it detects), zip-slip-guarded uploads, capped subprocess timeouts, structured JSON logs with request IDs, and no stack traces in API responses.
