# URL-based (black-box) web scanning

This document describes the work done in response to the CTO review of
17 October 2026: making APISentinel able to scan a live website or API by
**URL alone** — no source code and no SQL script required — while reusing the
existing backend, dashboard, database and risk-scoring engine as instructed.
It covers the architecture, the authorization/SSRF model, the detection
methodology in each mode, how the three requested research papers informed
specific design decisions, what was tested, and what is still limited.

Everything in this document describes code that is in this repository and has
been run; numbers quoted are real outputs, not estimates (see
[Testing and evaluation](#testing-and-evaluation)).

## 1. Why: the review's main objective

> "The main objective is to make APISentinel work through a live website URL
> without requiring the user to upload the source code or SQL scripts...
> organizations generally do not share their application's source code."

Concretely, this required:

1. A scan interface that accepts a **URL**, not only uploaded files.
2. A way to **discover** pages, forms, HTTP endpoints and APIs from the
   running application itself.
3. Reuse of the existing FastAPI backend, dashboard, database and
   risk-scoring components "wherever practical" — not a rebuild.
4. Clear labelling of findings as **confirmed, suspected, or inconclusive**,
   since some checks need credentials or context a black-box scan may not
   have.
5. **Target authorization, scope validation, SSRF protection, request limits
   and scanner isolation** — the tool must not scan arbitrary sites without
   permission, and a scanned site must not be able to reach the scanner's own
   internal services.
6. A revised architecture and an updated technical document (this one).

## 2. What was added, in one sentence per piece

| Piece | File(s) | Role |
|---|---|---|
| Target authorization & SSRF guard | `backend/app/runtime_layer/safety.py` | The single gate every outbound probe passes through — allowlist, authorization, resolved-IP checks, redirect re-validation |
| Crawler | `backend/app/web_layer/crawler.py` | Finds pages, links, forms; same-origin, bounded, read-only |
| OpenAPI/GraphQL discovery | `backend/app/web_layer/openapi_discovery.py` | Finds a machine-readable spec if the target publishes one |
| Endpoint builder | `backend/app/web_layer/endpoint_builder.py` | Turns what was discovered into the exact `ParsedEndpoint` shape the rest of the pipeline already understands |
| Active probes | `backend/app/web_layer/active_probes.py` | Conservative, single-request, non-destructive checks (headers, sensitive paths, error/reflection signals) |
| JS-rendered-page discovery | `backend/app/web_layer/js_crawler.py` | Real headless-browser render, opt-in; finds links/forms/XHR calls that only exist after JavaScript runs |
| Web pipeline | `backend/app/web_layer/pipeline.py` | Orchestrates the above into one discovery pass |
| ZAP spider/active scan | `backend/app/runtime_layer/zap_client.py` (extended) | Wider discovery and, opt-in, a real attack-payload sweep |
| Scan orchestration | `backend/app/services/scan_service.py` (extended) | Wires web discovery into the existing static/LLM/runtime/risk-engine pipeline, unchanged |
| Data model | `backend/app/db/models.py`, `backend/alembic/versions/0002_url_scan_mode.py` | `Project.scan_mode/target_authorized/scope_config`, `Endpoint.discovered_via` |
| API | `backend/app/api/projects.py`, `backend/app/api/scans.py` | Create a project with a URL and no files; authorization endpoints |
| Dashboard | `frontend/src/pages/ProjectPage.tsx` and others | Scan-mode picker, authorization controls, evidence-level badges |

## 3. Architecture

```
                         ┌─────────────────────────────┐
                         │   Dashboard (React)         │
                         │   scan_mode: source|url|hybrid│
                         └──────────────┬──────────────┘
                                        │ REST + JWT
                         ┌──────────────▼──────────────┐
                         │   FastAPI backend            │
                         │   api/projects.py             │
                         │   api/scans.py                 │
                         └──────────────┬──────────────┘
                                        │ execute_scan()
            ┌───────────────────────────┼────────────────────────────┐
            │                           │                            │
   scan_mode=source             scan_mode=url/hybrid                 │
            │                           │                            │
┌───────────▼───────────┐   ┌───────────▼────────────────────┐       │
│ parser (AST + OpenAPI) │   │ web_layer (NEW)                 │      │
│ reads uploaded files   │   │  1. authorize target (SSRF-safe)│      │
└───────────┬────────────┘   │  2. discover OpenAPI/GraphQL    │      │
            │                │  3. crawl (links, forms)        │      │
            │                │  4. build ParsedEndpoint list    │      │
            │                │  5. active probes (headers, ...) │      │
            │                │  6. optional: ZAP spider/active  │      │
            │                └───────────┬────────────────────┘       │
            └───────────────┬────────────┘                            │
                             │  ParsedEndpoint[]  (UNCHANGED SHAPE)     │
            ┌────────────────▼────────────────┐                        │
            │ static_layer (Bandit/Semgrep/    │                        │
            │ structural — unchanged)           │                        │
            │ llm_layer (unchanged)             │                        │
            │ runtime_layer (unchanged, now     │                        │
            │  also drives the differential     │                        │
            │  BOLA probe against web-discovered│                        │
            │  endpoints)                        │                        │
            │ risk_engine (unchanged)            │                        │
            └────────────────┬────────────────┘                        │
                             │                                          │
                     Finding rows (evidence_level computed, no new      │
                     column — see §5) ───────────────────────────────────┘
```

The key design decision is the one arrow labelled **"ParsedEndpoint[]
(UNCHANGED SHAPE)"**: `web_layer.endpoint_builder` turns whatever was
discovered — an OpenAPI operation, a crawled page, a submitted form — into the
exact same `ParsedEndpoint` dataclass the source-mode AST parser already
produces, with `source_code` holding a readable description of *observed*
behaviour instead of real Python. Every layer below that point (static,
LLM, runtime, risk engine) is **completely unmodified** by this work; two
small, independently-justified bug fixes aside (§8), their code is identical
to before the review.

## 4. Target authorization, scope and SSRF protection

All of this lives in one module, `app.runtime_layer.safety`, used by both the
differential runtime tester and the web crawler — not duplicated.

### 4.1 Two ways a target becomes reachable

1. **Operator allowlist** (`RUNTIME_TARGET_ALLOWLIST`). An exact host[:port]
   the operator typed in deliberately — this is how the bundled demo target
   (`vulnapi:8001`, itself a private Docker-internal address) stays scannable
   without weakening anything else.
2. **Authorized public target.** A host *not* on that list can only be scanned
   when **both**:
   - the operator has switched public-target scanning on at all
     (`ALLOW_PUBLIC_TARGETS=true`, off by default), **and**
   - the project owner has recorded authorization for that specific project
     (`Project.target_authorized`), through one of:
     - `POST /api/projects/{id}/authorization/confirm` — an explicit
       statement ("I confirm I am authorized to test this target"), logged
       with a timestamp (`authorization_confirmed_at`) and method
       (`"manual"`);
     - `POST /api/projects/{id}/authorization/verify` — a stronger,
       domain-verification-style proof: publish a per-project random token at
       `/.well-known/apisentinel-authorization.txt` on the target, and the
       server fetches and checks it before marking the project authorized
       (`"well-known-token"`).

Neither path is implied by the other. A url-mode project with
`target_authorized=False` cannot be scanned, full stop — enforced at scan
creation (`api/scans.py`, a `403` before the background job even starts) and
again inside `web_layer.pipeline.run_web_discovery` itself, so the control
holds regardless of which code path calls it.

### 4.2 SSRF protection

Every hostname, allowlisted or not, that is reachable as a *public* target has
every one of its resolved IP addresses checked
(`safety.resolve_public_ips`) against:

- private, loopback, link-local, multicast, reserved and unspecified ranges
  (Python's `ipaddress` classification), plus
- the IPv4 carrier-grade NAT block (`100.64.0.0/10`) and the cloud metadata
  address (`169.254.169.254`) named explicitly.

This is the OWASP SSRF Prevention Cheat Sheet's headline control — allowlist
the destination, then validate the *resolved* address, not just the
hostname string — because a hostname can resolve to more than one address
(DNS rebinding) and only one of them needs to be private to be a usable
pivot.

**Every link the crawler follows, and every HTTP redirect, is re-validated
independently** (`safety.assert_link_allowed`): it must stay on the same host
as the authorized primary target (or be separately allowlisted), and its own
resolved address is checked again. A page on the authorized target therefore
cannot smuggle the crawler onto a different host, or onto the scanner's own
internal services, by linking or redirecting to them — satisfying the
review's "must not allow a target website to access the scanner's internal
services."

### 4.3 Scope and request limits

- `ScopeConfig.max_pages` / `max_depth` bound how much of a site is crawled
  (operator ceiling: `WEB_MAX_PAGES`, `WEB_MAX_CRAWL_DEPTH`).
- `WEB_REQUEST_DELAY_MS` adds a small delay between requests.
- `include_patterns` / `exclude_patterns` restrict discovery to parts of a
  site's path space.
- The crawler **never submits a form**; it only records its action, method
  and field names. Submitting an unknown form is indistinguishable from
  fuzzing and is intentionally kept separate (§5.4, §5.5).
- Active probes send at most a handful of extra, single-shot requests per
  check (§5.4), not a payload library.

### 4.4 Scanner isolation

The demo/vulnerable target (`vulnapi`) is never the thing being protected
*from* — it is the thing a real deployment must never expose publicly (see
`docs`/`README.md`'s production checklist, unchanged by this work). What is
new here is the reverse direction: protecting the scanner, and the rest of
the Docker network, from a target that tries to redirect or link the crawler
somewhere it should not go — covered by §4.2 and §4.1 together, enforced on
every single outbound request, not only the first one.

## 5. Detection methodology by mode

| Layer | `source` mode | `url` / `hybrid` mode |
|---|---|---|
| Endpoint discovery | AST parse of uploaded code (+ optional OpenAPI spec) | OpenAPI/Swagger auto-discovery first (§5.1), then crawling (§5.2); merged, spec wins on overlap |
| Static analysis | Bandit + Semgrep on real files, plus structural regex checks on real code | Bandit/Semgrep have no files to run on (none uploaded); structural checks still run, but against a *description of observed behaviour* rather than real code, so they see far less — code-level patterns (e.g. "compares `user.id` to the path parameter") are only visible in source mode |
| AI reasoning | Reads real source code | Reads the same observed-behaviour description used for structural checks (headers, status, declared OpenAPI security, form fields) |
| Runtime validation | Unchanged: differential two-user BOLA/BFLA tests, ZAP passive scan | Identical code, now also exercising web-discovered endpoints — this is where url-mode recovers much of the ground it loses elsewhere, because a black-box scan can prove a lot by *testing* even when it cannot *read* |
| Active probes | N/A | New: security headers, sensitive-path inventory, single-shot error/reflection signals (§5.4) — safe, always on |
| Risk fusion | Unchanged Noisy-OR fusion | Unchanged — a new finding `source="web"` is treated like any other source with neutral weight; no fusion code was modified |

### 5.1 OpenAPI/Swagger/GraphQL discovery (`web_layer/openapi_discovery.py`)

Tries a short, ordered list of common spec paths
(`/openapi.json`, `/v3/api-docs`, `/swagger.json`, ...) and one standard,
read-only GraphQL introspection query. A found spec is far more precise than
anything inferred from crawled HTML — declared parameters, security schemes,
response codes — so it is tried first and wins on overlap with the crawler.
An introspectable GraphQL endpoint is itself reported as a finding (API8):
introspection left open in production exposes the entire schema.

### 5.2 Crawling (`web_layer/crawler.py`)

A same-origin, SSRF-revalidated, bounded crawler using `httpx` +
BeautifulSoup. Finds links and forms; records a form's method, action and
field names without ever submitting it. Redirects are not auto-followed —
each `Location` header is validated like any other link before being queued,
implementing the Cheat Sheet's "re-validate on every redirect" literally
rather than trusting a one-time check.

### 5.3 Runtime validation reused, not rebuilt

The differential BOLA/BFLA tester (`runtime_layer/differential.py`) already
worked purely in terms of `(method, path)` and a base URL — it had no
dependency on source code. It needed **zero changes** to work against
web-discovered endpoints; the only work was feeding it the right input
(§3's "UNCHANGED SHAPE" decision). Two real, pre-existing bugs in it were
found and fixed while verifying this (§8) — unrelated to url-mode itself, but
exposed by actually exercising it end-to-end for the first time.

### 5.4 Active probes (`web_layer/active_probes.py`)

Four conservative, always-on checks, each issuing at most a handful of extra
GET requests:

1. **Security headers** — HSTS, CSP, `X-Content-Type-Options`,
   `X-Frame-Options`/frame-ancestors, permissive CORS with credentials, a
   version-disclosing `Server` header.
2. **Sensitive path inventory** — a short, curated list (`/.env`,
   `/.git/config`, `/actuator/env`, ...), flagged only when the response body
   actually matches the shape of real sensitive content, to avoid false
   positives on a catch-all 200 page.
3. **Single-shot error/reflection signal** — append one apostrophe to an
   existing parameter and look for a known stack-trace or SQL-error
   signature; send one unique inert marker as a parameter and check whether
   it is reflected unescaped. This is the standard black-box "error-based"
   technique the injection-detection literature describes (§6.3) — not a
   payload sweep.

Every finding here is capped at confidence ≤ 0.65 and is explicitly described
in its own text as a single-probe, corroborating signal — never claimed as
proof. This cap is a design response to Althunayyan et al. (2022): see §6.3.

### 5.5 JavaScript-rendered-page discovery (`web_layer/js_crawler.py`)

Per-scan opt-in (`scope_config.use_playwright`, default off). Renders a
bounded number of pages (`js_max_pages`, default 15, capped at `WEB_MAX_PAGES`)
in real headless Chromium via Playwright and, after the page settles
(`networkidle`), reads back:

- every `<a href>` present in the *rendered* DOM, not just the raw HTML;
- every `<form>` present in the rendered DOM, the same way the plain crawler
  records one (action, method, field names — never submitted);
- every XHR/`fetch` request the page itself made while loading.

Each of these is built into the same `ParsedEndpoint` shape as everything
else (`endpoint_builder.build_from_js_render`), so a link, form or API call
that is invisible to a plain HTTP GET still reaches static analysis, the AI
layer and runtime validation exactly like any other discovered endpoint. On
overlap with the OpenAPI-sourced or plain-crawled endpoint lists, the more
precise source wins (OpenAPI > plain crawl > JS-rendered), since a page
rendered without interacting with the application can still miss context a
declared spec or a direct HTML link already captured accurately.

Self-gating: `js_crawler.is_available()` checks both that the `playwright`
package is importable *and* that a Chromium build can actually be launched.
If either is false (for example, the Dockerfile's `playwright install
chromium` step was removed to keep the image smaller), a scan that requests
`use_playwright` simply records a warning and proceeds with everything else
unaffected — this is never a hard failure.

Every URL this renderer visits, including ones it discovers only after
rendering a page, goes through the identical `assert_link_allowed` SSRF/scope
check as the plain crawler (§4) — rendering with a real browser does not
create a separate trust boundary.

### 5.6 ZAP, extended (`runtime_layer/zap_client.py`)

- **Spider** (opt-in per scan, `use_zap_spider`) — wider link discovery, no
  attack traffic.
- **Active Scan** (opt-in **twice over** — the operator must set
  `ZAP_ENABLE_ACTIVE_SCAN=true`, *and* the scan must request
  `run_active_scan`) — a real payload sweep. This is the one capability in
  the whole feature that is genuinely intrusive, and it is the only one with
  two independent switches rather than one.
- Passive scan is unchanged from before this work.

### 5.7 Confirmed / suspected / inconclusive

The review asked for findings to be clearly labelled this way. Implemented as
a **computed field** on the API response (`FindingOut.evidence_level`,
`backend/app/schemas.py`) derived entirely from fields the risk engine
already sets — **no fusion-engine change, no new column**:

```python
if not needs_manual_review and confidence >= 0.90:  return "confirmed"
if confidence < 0.35:                                return "inconclusive"
else:                                                 return "suspected"
```

`needs_manual_review` is only cleared when the runtime layer actually
confirmed a finding; a runtime-refuted finding is demoted to a low fused
confidence by the existing, unmodified fusion rules. The thresholds are
deliberately conservative — see §6.3.

## 6. How the three research papers shaped specific decisions

### 6.1 Alazmi & De Leon (2022), *A Systematic Literature Review on the
Characteristics and Effectiveness of Web Application Vulnerability Scanners*

Used to decide **how to measure the tool** rather than only how to build it:
the paper's emphasis on evaluating scanners against known, labelled targets
rather than by counting findings is why this review produced an actual
precision/recall/F1 comparison (§7) against the existing
`datasets/ground_truth.yml`, instead of a features list. It also informed the
decision to keep source-mode and url-mode as explicitly separate evaluation
rows rather than one blended number — a literature-review-level point the
paper makes about scanners being compared on inconsistent bases.

### 6.2 Alsaidi, Alhuzali & Bamasag (2022), *Effective and Scalable Black-Box
Fuzzing Approach for Modern Web Applications*

Used for **discovery design**: the paper's focus on application exploration
and form interaction for modern (JavaScript-heavy) web applications is why
form discovery was built as a first-class part of the crawler (recording
method/action/fields, §5.2), and why JavaScript-rendered-page discovery
(§5.5) renders real pages in headless Chromium rather than only reading raw
HTML — a single-page application can have nothing but an empty `<div>` in its
initial response. Two complementary paths are available:

- OWASP ZAP's own **Ajax Spider** (`use_zap_spider`) — reuses infrastructure
  already in the stack.
- A dedicated **Playwright-based renderer** (`web_layer/js_crawler.py`,
  `use_playwright`) — finds links, forms and XHR/fetch calls that exist only
  after a page's own JavaScript runs, verified in this project's own tests
  against a page whose content is added entirely by a script (see §7).

Both are **per-scan opt-in, off by default** — rendering real pages is
meaningfully slower and heavier than every other check in this project, and
the deployment VM this project runs on has its own, separately documented
resource constraints (it cannot use its host's GPU, and has limited headroom
generally). Opt-in keeps that cost out of a default scan while making the
capability fully available when a target actually needs it.

### 6.3 Althunayyan, Saxena, Li & Gope (2022), *Evaluation of Black-Box Web
Application Security Scanners in Detecting Injection Vulnerabilities*

This paper's two findings directly shaped the single-probe design of §5.4 and
the confidence caps throughout this feature:

1. Black-box scanners **miss** a meaningful share of real injection flaws
   (because they cannot see the query-construction code) — accepted as an
   honest limitation, documented in §5, §10, rather than compensated for with
   a larger payload set that would change the tool's risk profile.
2. Scanners that fire large payload libraries **over-report** findings a
   reviewer cannot trust without re-testing. This is why `active_probes.py`
   uses exactly **one** benign payload per check, never a payload library,
   and why every finding it produces is capped below the "confirmed"
   threshold (§5.6) — the paper's conclusion is treated as a design
   constraint, not just a citation.

### 6.4 OWASP resources

- **Web Security Testing Guide** — the general shape of §5.4's checks
  (header audit, information disclosure, error-based signal) follows its
  injection and configuration-testing chapters at a conservative, single-probe
  level.
- **API Security Top 10 (2023)** — unchanged from the rest of the project;
  every new finding is still categorised against it.
- **OWASP ZAP** — extended, not replaced (§5.5).

## 7. Testing and evaluation

Everything below was actually run in this repository's own test suite (see
`backend/tests/`) and is re-runnable.

| File | What it proves |
|---|---|
| `test_ssrf_safety.py` | 15 unit tests: allowlist matching, public-target gating, private/reserved IP blocking (including the cloud metadata address and CGNAT), scheme restriction, redirect/link re-validation |
| `test_web_layer.py` | Discovery against the bundled live target finds 15+ real endpoints from its OpenAPI spec alone; SSRF checks raise before any request is sent; the full static→runtime→fusion chain, fed only from URL-discovered endpoints, lands on the target's real, documented BOLA bug with ≥ 0.9 confidence and `runtime_confirmed=True` |
| `test_scan_service_url_mode.py` | The same proof, but through the real, DB-backed `execute_scan()` — a `scan_mode="url"` `Project` with no artifacts, scanned end-to-end, persists endpoints and a runtime-confirmed `Finding` row in Postgres; a second test proves an unauthorized target fails the scan closed (`status="failed"`), not silently |
| `test_api_url_mode.py` | The same proof again, through the real HTTP API (`TestClient`): project creation without files, the authorization endpoints, scan creation being rejected (`403`) for an unauthorized target, and a full scan reaching `evidence_level: "confirmed"` in the JSON response |
| `test_evaluation_report.py` | Computes real precision/recall/F1 for **both modes** against `datasets/ground_truth.yml`, using `evaluation/evaluate.py`'s own scoring function (imported, not reimplemented); writes `evaluation/results/mode_comparison.md` |
| `test_js_crawler.py` | A real headless-browser render against a page whose link, form and API call exist only after its own `<script>` runs — proving they are found — plus a full-pipeline test that those three show up as real discovered endpoints; skips itself if Chromium is not installed |
| `test_zap_active_scan.py` | Spider and Active Scan against a fake-but-real ZAP REST API (actual HTTP calls, real response parsing): the two-switch gate blocks Active Scan when either switch is off, runs and returns a parsed finding when both are on, and degrades to an empty result (no crash) when ZAP is unreachable |

### 7.1 Real numbers (one run; `evaluate.py --runs N` averages, this does not)

| Mode | Endpoints found | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| source | 17 | 11 | 6 | 7 | 4 | 0.65 | 0.61 | 0.63 |
| url | 18 | 7 | 6 | 11 | 4 | 0.54 | 0.39 | 0.45 |

Read honestly: url-mode finds slightly more endpoints (it discovers a couple
the AST parser does not surface the same way) but has lower recall — it
misses more true positives, exactly the gap §5 and §6.3 describe, because it
cannot read the business logic that only exists in source. Both modes have
identical false-positive behaviour on negative controls (`fpr = 0`). This
matches the expected, literature-backed trade-off rather than claiming
black-box scanning matches white-box — see §10.

To reproduce: `cd backend && DATABASE_URL=postgresql+psycopg://... pytest tests/test_evaluation_report.py -s`,
or, inside a running deployment, `make evaluate` / `python evaluation/evaluate.py --project-name "URL scan only"`
for the url-mode demo project specifically (the `--project-name` flag is new,
added because bootstrap now seeds two demo projects with a target URL — see §9).

## 8. Bugs found and fixed while verifying the existing scan workflow

The review noted that "the current project document indicates that some scan
results, automated tests and detection metrics are still pending
verification." Actually exercising the runtime differential tester end-to-end
for the first time (building url-mode required doing exactly that) surfaced
two real, pre-existing bugs, both fixed:

1. **Login field mismatch.** `differential.py` always POSTed a JSON field
   literally called `username`; the bundled demo target's `/login` expects
   `email`. The demo project's seeded credentials also used `owned_ids`
   (plural) while the tester read `object_id` (singular), and a key named
   `"accounts"` where the tester read `"users"`. Net effect: differential
   login against the bundled demo target **never worked**, in source mode or
   otherwise, before this fix. Fixed with a configurable
   `identifier_field` (defaults to `"username"`, unchanged for anyone already
   relying on that), and the demo credentials corrected to match.
2. **Vacuous BOLA confirmation.** The BOLA probe ran for any API1/API5
   candidate with two accounts, even when the path had no `{...}`
   placeholder to substitute — both the "control" and "probe" request then
   hit the identical URL and trivially matched, reporting a false
   `"confirmed"` BOLA on a flat route (e.g. an admin endpoint with no object
   id in its path). Fixed with a guard in `runtime_layer/runner.py` that
   skips the degenerate case instead of reporting it; regression-tested in
   `test_web_layer.py::test_degenerate_bola_probe_is_skipped_not_falsely_confirmed`.

Both are documented here rather than fixed silently, per this project's own
"important corrections and lessons learned" practice.

A third, frontend-only issue was also found and fixed: the dashboard's scan
page looked up layer status under the key `"parse"`, but the backend has
always written it under `"parser"` — so that status card showed nothing
useful even before this review. Fixed in `ScanPage.tsx` (§9).

A fourth, test-infrastructure-only issue surfaced while adding more test
files: `test_core.py` configured the runtime allowlist via
`os.environ.setdefault("RUNTIME_TARGET_ALLOWLIST", ...)` at module import
time. Because `app.config.settings` is a singleton built once, on whichever
test file happens to trigger its first import, that line was silently
becoming the *permanent* initial allowlist for the entire test session, not
just a default for its own test — so later test files could lose access to
hosts they needed depending on file collection order. Fixed by setting
`settings.runtime_target_allowlist` directly inside the one test that needs a
different value, with a proper save/restore, and removing the
process-environment line entirely (`backend/tests/test_core.py`).

## 9. What changed, file by file

See `CHANGELOG.md` for the complete list with reasoning for every file. In
brief: new `backend/app/web_layer/` package (6 files), extended
`runtime_layer/safety.py` and `zap_client.py`, one new Alembic migration, new
columns on `Project` and `Endpoint`, extended `schemas.py`/`api/projects.py`/
`api/scans.py`/`services/scan_service.py`, a second seeded demo project
(`bootstrap.py`) so url-mode is demonstrable without any manual setup,
7 new backend test files, and dashboard updates (`ProjectPage.tsx`,
`ScanPage.tsx`, `FindingPage.tsx`, `Projects.tsx`, `api.ts`).

## 10. Known limitations and future work

Stated plainly, not hidden:

- **Recall is lower in url-mode than source-mode** (§7.1) — an inherent,
  literature-backed property of black-box scanning (§6.3), not a bug. Runtime
  validation narrows this gap but does not close it.
- **Structural/LLM analysis sees far less in url-mode** (§5, table row 2) —
  it reasons over *observed* behaviour, not real code.
- **JavaScript-rendered-page crawling and ZAP Active Scan are both built and
  tested (§5.5, §5.6), but both are per-scan opt-in, off by default** —
  rendering real pages and running a real attack-payload sweep are
  meaningfully heavier/more intrusive than everything else in this project;
  a reviewer who wants either for a specific scan turns it on explicitly
  rather than paying that cost (or that risk, for Active Scan) on every scan.
- **The differential probe needs one object id per test account**, used
  uniformly across every candidate endpoint (pre-existing design, not changed
  here) — it will not correctly test two resources that use unrelated id
  spaces (e.g. order ids vs invoice ids) with a single pair of accounts. Noted
  as a pre-existing limitation, not fixed in this review (out of scope — see
  §8 for what *was* fixed and why).
- **The well-known-token authorization check is optional**, not mandatory —
  the manual-confirmation path is the default and is a process control, not a
  technical one; a determined user can mis-state authorization the same way
  they could lie on a paper form. This is an explicit, documented trade-off,
  not an oversight.
- **Active Scan is real attack traffic.** It is behind two independent
  switches for exactly that reason and is not part of the default demo flow.
- **Evaluation numbers are a single run**, not averaged (§7.1) — a
  statistically stronger estimate needs `evaluate.py --runs N` against a live
  deployment.
