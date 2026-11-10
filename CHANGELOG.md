# Changelog: URL-based (black-box) scanning

Response to the CTO review of 17 October 2026. See **docs/WEB_SCANNING.md**
for the full architecture and reasoning; this file is the file-by-file
record of what changed and why.

## New files

| File | Purpose |
|---|---|
| `backend/app/web_layer/__init__.py` | Package export: `run_web_discovery` |
| `backend/app/web_layer/crawler.py` | Same-origin, SSRF-revalidated, bounded black-box crawler (links, forms) |
| `backend/app/web_layer/openapi_discovery.py` | Finds a live OpenAPI/Swagger spec or a GraphQL introspection endpoint |
| `backend/app/web_layer/endpoint_builder.py` | Converts discovered specs/pages into `ParsedEndpoint` — the existing parser's own output type |
| `backend/app/web_layer/active_probes.py` | Conservative, single-request security-header/info-disclosure/error-signal/reflection checks |
| `backend/app/web_layer/pipeline.py` | Orchestrates discovery → probes → optional JS render / ZAP spider/active scan into one pass |
| `backend/app/web_layer/js_crawler.py` | Real headless-browser (Playwright/Chromium) render, opt-in; finds links, forms and XHR/fetch calls that only exist after JavaScript runs |
| `backend/alembic/versions/0002_url_scan_mode.py` | Adds `Project.scan_mode/target_authorized/authorization_*/scope_config`, `Endpoint.discovered_via`; existence-checked so it is safe on both a fresh install and an existing database |
| `backend/tests/test_ssrf_safety.py` | 15 unit tests for the authorization/SSRF gate |
| `backend/tests/test_web_layer.py` | 7 tests: discovery + full pipeline against the live bundled target, including the real BOLA confirmation and the degenerate-BOLA regression test |
| `backend/tests/test_scan_service_url_mode.py` | 2 tests: the real DB-backed `execute_scan()` for `scan_mode="url"`, success and fail-closed paths |
| `backend/tests/test_api_url_mode.py` | 7 tests: the full HTTP API, including the authorization endpoints |
| `backend/tests/test_evaluation_report.py` | Real precision/recall/F1 for both modes against the ground truth; writes `evaluation/results/mode_comparison.md` |
| `backend/tests/test_js_crawler.py` | 4 tests: real headless-browser render finds a link/form/XHR call that exist only after JavaScript runs; respects `max_pages`; degrades gracefully when Chromium is not installed; those endpoints reach the full pipeline's output |
| `backend/tests/test_zap_active_scan.py` | 7 tests against a fake-but-real ZAP REST API: spider, Active Scan's two-switch gate (both off, one off, both on), graceful behaviour when ZAP is unreachable |
| `docs/WEB_SCANNING.md` | Architecture, SSRF/authorization model, methodology, research-paper mapping, test results, limitations |
| `CHANGELOG.md` | This file |

## Modified files

| File | Change | Why |
|---|---|---|
| `backend/app/runtime_layer/safety.py` | Rewritten: adds `SSRFBlocked`, `resolve_public_ips`, `assert_link_allowed`, and a public-target path on `assert_target_allowed` (gated by `ALLOW_PUBLIC_TARGETS` + `Project.target_authorized`) | Single shared gate for both the runtime tester and the new crawler; implements the review's SSRF/authorization requirement |
| `backend/app/runtime_layer/__init__.py` | Exports the new names | |
| `backend/app/runtime_layer/zap_client.py` | Adds `spider()`, `active_scan()`; factors the alert-fetch tail into `_alerts_for()` shared by passive and active scan | Wider discovery and an opt-in, two-switch-gated attack sweep |
| `backend/app/runtime_layer/differential.py` | `identifier_field` option; accepts `email` as an identifier; accepts `owned_ids` as a fallback for `object_id` | **Bug fix** — see "Bugs fixed" below |
| `backend/app/runtime_layer/runner.py` | `_candidates` skips an API1/API5 BOLA probe when the path has no `{...}` placeholder | **Bug fix** — see "Bugs fixed" below |
| `backend/app/db/models.py` | New `Project` columns (`scan_mode`, `target_authorized`, `authorization_method`, `authorization_token`, `authorization_confirmed_at`, `scope_config`); new `Endpoint.discovered_via` | Backing store for the new mode |
| `backend/app/config.py` | New settings: `allow_public_targets`, `web_max_pages`, `web_max_crawl_depth`, `web_request_timeout_seconds`, `web_request_delay_ms`, `web_user_agent`, `zap_enable_active_scan` | Operator-level controls, all off/conservative by default |
| `backend/app/schemas.py` | `ScanMode`, `ScopeConfig`; `ProjectCreate/Update/Out/Detail` extended; `ScanCreate` gets `run_active_probes/use_zap_spider/run_active_scan`; `FindingOut.evidence_level` computed field | API surface for the new mode; confirmed/suspected/inconclusive labelling with no new column |
| `backend/app/api/projects.py` | `scan_mode`/target-URL validation on create and update; `POST /{id}/authorization/confirm`; `POST /{id}/authorization/verify` | URL-mode project creation without artifacts; the two authorization paths |
| `backend/app/api/scans.py` | Artifact requirement relaxed for url/hybrid projects (requires a target URL instead); early `assert_target_allowed` check (403) before a scan is queued | Removes the "must upload source" requirement for URL mode; fails closed before the background job starts |
| `backend/app/services/scan_service.py` | `_persist_endpoints` factored out of `reparse_project` and reused for web-discovered endpoints; new branch in `execute_scan` runs `web_layer.run_web_discovery` for url/hybrid projects and merges its endpoints into the existing pipeline | Wires discovery into static/LLM/runtime/risk-engine **without changing those layers** |
| `backend/app/bootstrap.py` | `_DEMO_RUNTIME_CREDENTIALS` extracted and corrected (see bug fix below); new `seed_demo_url_project()`, called from `main()` | Second demo project so url-mode is demonstrable with no manual setup; and the credential fix applies to both demo projects identically |
| `backend/requirements.txt` | `beautifulsoup4==4.12.3`, `lxml==5.3.0`, `playwright==1.56.0` | Crawler and JS-render dependencies |
| `backend/app/web_layer/endpoint_builder.py` | Adds `build_from_js_render`; `merge()` now takes any number of endpoint lists in priority order | Folds JS-discovered endpoints into the same unified list |
| `backend/Dockerfile` | `RUN python -m playwright install --with-deps chromium` | Installs the headless browser JS-rendering needs; documented as removable (adds ~300-400 MB) |
| `backend/tests/test_core.py` | Removed the `os.environ.setdefault("RUNTIME_TARGET_ALLOWLIST", ...)` line entirely; `test_runtime_allowlist` sets `settings.runtime_target_allowlist` directly with save/restore | **Test-isolation fix** — see "Bugs fixed" below |
| `evaluation/evaluate.py` | `demo_project()` takes an optional name filter and is deterministic when more than one project has a target URL; `--project-name` CLI flag; `run_scan` sets `run_active_probes` for url/hybrid projects | Needed once bootstrap seeds two projects with a target URL; lets the harness target either one explicitly |
| `.env.example` | New variables for all of the above, with explanations | |
| `docker-compose.yml` | Passes the new variables through to the `backend` service | Otherwise setting them in `.env` would have no effect |
| `Makefile` | `evaluate-url` target; comment on `test-backend` about Postgres unlocking more tests | |
| `.github/workflows/ci.yml` | New `backend-postgres` job (Postgres 16 service container, migrate, full test suite) | The sqlite job alone skips every URL-mode DB-integration test |
| `README.md` | New URL-mode section, quick-start mentions both demo projects, evaluation/production-checklist updates, layout updated | |
| `frontend/src/api.ts` | New types: `ScanMode`, `ScopeConfig`, `EvidenceLevel`, `AuthorizationStatus`; `Project`/`ProjectDetail`/`Endpoint`/`Finding`/`Scan.layer_status` extended | |
| `frontend/src/pages/ProjectPage.tsx` | New "Target & scan mode" card (mode picker, target URL, authorization confirm/verify); source-upload card hidden in pure url mode; endpoints table shows "Discovered via"; scan form shows the url-mode-only options | |
| `frontend/src/pages/ScanPage.tsx` | **Bug fix**: layer key `"parse"` → `"parser"` (see below); shows discovery metadata (pages crawled, spec found) on that card; Evidence-level column, badge and filter on the findings table | |
| `frontend/src/pages/FindingPage.tsx` | Evidence-level badge | |
| `frontend/src/pages/Projects.tsx` | Scan-mode badge; authorization badge for url/hybrid projects | |

## Bugs found and fixed while verifying the existing scan workflow

The review noted some scan results and metrics were still pending
verification. Building url-mode required actually exercising the runtime
differential tester end-to-end for the first time, which surfaced three real,
pre-existing issues — none specific to url-mode, all now fixed and
regression-tested:

1. **Login field mismatch** (`differential.py` + `bootstrap.py`). The tester
   always sent a JSON field literally called `username`; the bundled demo
   target expects `email`. The seeded demo credentials also used `owned_ids`
   where the tester read `object_id`, and a key `"accounts"` where it read
   `"users"`. Net effect: differential login against the bundled demo target
   never worked before this fix, in source mode either. Fixed with a
   configurable `identifier_field` (default unchanged: `"username"`).
2. **Vacuous BOLA confirmation** (`runner.py`). The BOLA probe ran even for a
   path with no `{...}` placeholder, so the "control" and "probe" requests
   hit the identical URL and trivially matched — a false `"confirmed"` BOLA
   on a flat route. Fixed with a one-line guard;
   `test_degenerate_bola_probe_is_skipped_not_falsely_confirmed` asserts it
   stays fixed.
3. **Dashboard layer-key typo** (`ScanPage.tsx`). The scan page looked up
   `scan.layer_status["parse"]`; the backend has always written `"parser"`.
   That status card showed nothing useful for any scan, in either mode,
   before this fix.

A fourth item is a **test-isolation fix, not a product bug**, found twice —
the first pass fixed the symptom, adding the JS-crawler and ZAP test files
later exposed the real root cause: `test_core.py` configured the runtime
allowlist via `os.environ.setdefault("RUNTIME_TARGET_ALLOWLIST", ...)` at
module import time. Because `app.config.settings` is a singleton built once
on first import, that line was silently becoming the *permanent* initial
allowlist for the whole test session — not merely a default scoped to its own
test — so whichever test file happened to trigger the first import, and in
what order, changed what later files could reach. Fully fixed by removing
that environment-variable line and setting `settings.runtime_target_allowlist`
directly inside the one test that needs a different value, save/restore
included.

## Verification performed

See `docs/WEB_SCANNING.md` section 7 for detail. In summary: 53 backend
pytest tests pass against a real Postgres database (42 against SQLite, which
skips the 11 tests that genuinely need Postgres's JSONB/UUID columns — both
counts reproducible, run twice each), the frontend TypeScript build and its
existing Vitest suite pass, Alembic migration 0002 was verified on a fresh
database and as an upgrade from an existing 0001-only database (both
directions, including downgrade), a real precision/recall/F1 comparison was
run for both scan modes against the existing ground-truth dataset and written
to `evaluation/results/mode_comparison.md`, JavaScript-rendered-page discovery
was proven against a page whose content exists only after its own script
runs, and ZAP's spider and Active Scan were exercised against a real HTTP
server standing in for ZAP's REST API, including the two-switch gate in every
combination.
