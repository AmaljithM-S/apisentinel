import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { AuthorizationStatus, ProjectDetail, Scan, ScanMode, api } from "../api";
import { StatusPill } from "../components/ui";

export default function ProjectPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const [p, setP] = useState<ProjectDetail | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [filename, setFilename] = useState("app.py");
  const [source, setSource] = useState("");
  const [repo, setRepo] = useState("");
  const [opts, setOpts] = useState({
    run_static: true, run_llm: true, run_runtime: false,
    run_active_probes: true, use_zap_spider: false, run_active_scan: false,
    use_playwright: false,
  });
  const [baseUrl, setBaseUrl] = useState("");
  const [creds, setCreds] = useState("");
  const [busy, setBusy] = useState(false);

  // Target & scan mode (project-level; saved via PATCH, independent of the
  // per-scan "Run a scan" form below).
  const [scanMode, setScanMode] = useState<ScanMode>("source");
  const [targetUrl, setTargetUrl] = useState("");
  const [authStatement, setAuthStatement] = useState("I confirm I am authorized to test this target.");
  const [maxPages, setMaxPages] = useState(60);

  const load = useCallback(async () => {
    try {
      const [proj, sc] = await Promise.all([
        api<ProjectDetail>(`/api/projects/${id}`),
        api<Scan[]>(`/api/projects/${id}/scans`),
      ]);
      setP(proj);
      setScans(sc);
      setBaseUrl((b) => b || proj.runtime_base_url || "");
      setCreds((c) => c || (proj.runtime_credentials ? JSON.stringify(proj.runtime_credentials, null, 2) : ""));
      setScanMode(proj.scan_mode);
      setTargetUrl((t) => t || proj.runtime_base_url || "");
      setMaxPages(proj.scope_config?.max_pages ?? 60);
      setOpts((o) => ({ ...o, run_runtime: o.run_runtime || proj.scan_mode === "url" }));
    } catch (e) {
      setError((e as Error).message);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const urlMode = scanMode === "url" || scanMode === "hybrid";

  async function saveTarget() {
    await run(() => api(`/api/projects/${id}`, {
      method: "PATCH",
      body: JSON.stringify({
        scan_mode: scanMode,
        runtime_base_url: targetUrl || null,
        scope_config: urlMode ? { max_pages: maxPages } : undefined,
      }),
    }), "Scan mode and target saved.");
  }

  async function confirmAuthorization() {
    await run(() => api<AuthorizationStatus>(`/api/projects/${id}/authorization/confirm`, {
      method: "POST", body: JSON.stringify({ confirm: true, statement: authStatement }),
    }), "Authorization recorded.");
  }

  async function verifyAuthorization() {
    await run(() => api<AuthorizationStatus>(`/api/projects/${id}/authorization/verify`, {
      method: "POST",
    }), "Authorization verified via well-known token.");
  }

  async function run<T>(fn: () => Promise<T>, ok: string) {
    setError(""); setNotice(""); setBusy(true);
    try { await fn(); setNotice(ok); await load(); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }

  const pasteSource = (e: FormEvent) => {
    e.preventDefault();
    run(() => api(`/api/projects/${id}/artifacts/text`, {
      method: "POST", body: JSON.stringify({ filename, content: source, kind: filename.match(/\.(ya?ml|json)$/) ? "openapi" : "source" }),
    }).then(() => setSource("")), "Source added and parsed.");
  };

  const upload = (files: FileList | null) => {
    if (!files?.length) return;
    const fd = new FormData();
    Array.from(files).forEach((f) => fd.append("files", f));
    run(() => api(`/api/projects/${id}/artifacts`, { method: "POST", body: fd }), "Files uploaded and parsed.");
  };

  const importGit = (e: FormEvent) => {
    e.preventDefault();
    const fd = new FormData();
    fd.append("repo_url", repo);
    run(() => api(`/api/projects/${id}/artifacts/git`, { method: "POST", body: fd }), "Repository imported.");
  };

  async function startScan() {
    setError("");
    let credentials: Record<string, unknown> | undefined;
    if (opts.run_runtime && creds.trim()) {
      try { credentials = JSON.parse(creds); } catch { setError("Runtime credentials must be valid JSON."); return; }
    }
    setBusy(true);
    try {
      const body: Record<string, unknown> = {
        run_static: opts.run_static, run_llm: opts.run_llm, run_runtime: opts.run_runtime,
        runtime_base_url: opts.run_runtime ? baseUrl || null : null, runtime_credentials: credentials,
      };
      if (urlMode) {
        body.run_active_probes = opts.run_active_probes;
        body.use_zap_spider = opts.use_zap_spider;
        body.run_active_scan = opts.run_active_scan;
        body.use_playwright = opts.use_playwright;
      }
      const scan = await api<Scan>(`/api/projects/${id}/scans`, { method: "POST", body: JSON.stringify(body) });
      nav(`/scans/${scan.id}`);
    } catch (e) { setError((e as Error).message); setBusy(false); }
  }

  const canScan = urlMode ? !!p?.runtime_base_url && !!p?.target_authorized : (p?.endpoints.length ?? 0) > 0;

  if (!p) return error ? <p role="alert" className="error">{error}</p> : <p className="muted">Loading…</p>;

  return (
    <>
      <p><Link to="/">← Projects</Link></p>
      <h1>{p.name}</h1>
      {p.description && <p className="muted">{p.description}</p>}
      {error && <p role="alert" className="error">{error}</p>}
      {notice && <p role="status" className="notice">{notice}</p>}

      <section className="card">
        <h2>Target &amp; scan mode</h2>
        <p className="muted small">
          Source: scan uploaded code. Website URL: scan a live target by URL only — no source code or SQL script is
          needed. Hybrid: both, merged.
        </p>
        <fieldset className="stack">
          <legend className="sr-only">Scan mode</legend>
          <label className="check"><input type="radio" name="scan_mode" checked={scanMode === "source"} onChange={() => setScanMode("source")} /> Source code</label>
          <label className="check"><input type="radio" name="scan_mode" checked={scanMode === "url"} onChange={() => setScanMode("url")} /> Website URL only</label>
          <label className="check"><input type="radio" name="scan_mode" checked={scanMode === "hybrid"} onChange={() => setScanMode("hybrid")} /> Hybrid (source + URL)</label>
        </fieldset>
        {(scanMode === "url" || scanMode === "hybrid") && (
          <>
            <label>Target URL<input value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} placeholder="https://your-authorized-target.example" /></label>
            <label>Max pages to crawl<input type="number" min={1} max={500} value={maxPages} onChange={(e) => setMaxPages(Number(e.target.value))} /></label>
          </>
        )}
        <button onClick={saveTarget} disabled={busy}>Save</button>

        {(scanMode === "url" || scanMode === "hybrid") && (
          <div className="stack" style={{ marginTop: "1rem" }}>
            <h3>Authorization</h3>
            {p.target_authorized ? (
              <p className="notice" role="status">
                Authorized ({p.authorization_method === "well-known-token" ? "verified via well-known token" : "manually confirmed"}
                {p.authorization_confirmed_at ? `, ${new Date(p.authorization_confirmed_at).toLocaleString()}` : ""}).
              </p>
            ) : (
              <p className="error" role="alert">
                Not authorized yet. A non-allowlisted target cannot be scanned until you confirm authorization below.
              </p>
            )}
            <label>Statement<input value={authStatement} onChange={(e) => setAuthStatement(e.target.value)} /></label>
            <button onClick={confirmAuthorization} disabled={busy}>I confirm I&apos;m authorized to test this target</button>
            <details>
              <summary>Prove it automatically instead (optional, stronger)</summary>
              <p className="muted small">
                Publish this exact token at <code>{(targetUrl || p.runtime_base_url || "").replace(/\/$/, "")}/.well-known/apisentinel-authorization.txt</code>,
                then verify:
              </p>
              <p className="mono small">{p.authorization_token}</p>
              <button onClick={verifyAuthorization} disabled={busy}>Verify via well-known token</button>
            </details>
          </div>
        )}
      </section>

      <div className="grid2">
        <section className="card">
          <h2>Run a scan</h2>
          <fieldset className="stack">
            <legend className="sr-only">Analysis layers</legend>
            <label className="check"><input type="checkbox" checked={opts.run_static} onChange={(e) => setOpts({ ...opts, run_static: e.target.checked })} /> Static analysis (Bandit, Semgrep, structural)</label>
            <label className="check"><input type="checkbox" checked={opts.run_llm} onChange={(e) => setOpts({ ...opts, run_llm: e.target.checked })} /> AI contextual reasoning + business rules + STRIDE</label>
            <label className="check"><input type="checkbox" checked={opts.run_runtime} onChange={(e) => setOpts({ ...opts, run_runtime: e.target.checked })} /> Runtime differential validation</label>
            {opts.run_runtime && (
              <>
                <label>Target base URL (must be allowlisted)<input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="http://vulnapi:8001" /></label>
                <label>Test credentials (JSON)<textarea className="mono" rows={5} value={creds} onChange={(e) => setCreds(e.target.value)} /></label>
              </>
            )}
            {urlMode && (
              <>
                <label className="check"><input type="checkbox" checked={opts.run_active_probes} onChange={(e) => setOpts({ ...opts, run_active_probes: e.target.checked })} /> Active probes (headers, sensitive paths, single-shot injection/reflection checks — safe, read-only)</label>
                <label className="check"><input type="checkbox" checked={opts.use_zap_spider} onChange={(e) => setOpts({ ...opts, use_zap_spider: e.target.checked })} /> ZAP spider (wider link discovery)</label>
                <label className="check"><input type="checkbox" checked={opts.run_active_scan} onChange={(e) => setOpts({ ...opts, run_active_scan: e.target.checked })} /> ZAP Active Scan (intrusive — sends real attack payloads; also needs the operator to enable it)</label>
                <label className="check"><input type="checkbox" checked={opts.use_playwright} onChange={(e) => setOpts({ ...opts, use_playwright: e.target.checked })} /> Render JS pages (headless browser — finds links/forms/API calls that only exist after JavaScript runs; slower, needs Chromium installed on the backend)</label>
              </>
            )}
          </fieldset>
          <button onClick={startScan} disabled={busy || !canScan}>Start scan</button>
          {!canScan && (
            <p className="muted small">
              {urlMode ? "Set a target URL and confirm authorization above first." : "Add source code first — no endpoints were found yet."}
            </p>
          )}

          <h3>Scan history</h3>
          {scans.length === 0 ? <p className="muted">No scans yet.</p> : (
            <ul className="list">
              {scans.map((s) => (
                <li key={s.id}><Link to={`/scans/${s.id}`}>{new Date(s.started_at).toLocaleString()}</Link> <StatusPill status={s.status} /></li>
              ))}
            </ul>
          )}
        </section>

        {scanMode !== "url" && (
          <section className="card">
            <h2>Source code</h2>
            <form onSubmit={pasteSource} className="stack">
              <label>File name<input value={filename} onChange={(e) => setFilename(e.target.value)} required /></label>
              <label>Paste FastAPI source or an OpenAPI spec<textarea className="mono" rows={8} required value={source} onChange={(e) => setSource(e.target.value)} /></label>
              <button disabled={busy}>Add source</button>
            </form>
            <label className="stack">Or upload .py / .yaml / .json files or a .zip
              <input type="file" multiple accept=".py,.yaml,.yml,.json,.zip" onChange={(e) => upload(e.target.files)} disabled={busy} />
            </label>
            <form onSubmit={importGit} className="row">
              <label className="grow">Public Git repository<input type="url" value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="https://github.com/org/repo" required /></label>
              <button disabled={busy}>Import</button>
            </form>
            <h3>Artifacts ({p.artifacts.length})</h3>
            <ul className="list mono small">{p.artifacts.map((a) => <li key={a.id}>{a.filename} <span className="muted">[{a.kind}]</span></li>)}</ul>
          </section>
        )}
      </div>

      <section className="card">
        <h2>Discovered endpoints ({p.endpoints.length})</h2>
        <table>
          <thead><tr><th>Method</th><th>Path</th><th>Handler</th><th>Auth dependencies</th><th>Discovered via</th><th>Location</th></tr></thead>
          <tbody>
            {p.endpoints.map((e) => (
              <tr key={e.id}>
                <td className="mono">{e.method}</td><td className="mono">{e.path}</td><td>{e.handler_name}</td>
                <td>{e.auth_dependencies?.length ? e.auth_dependencies.join(", ") : <span className="sev-high-text">none</span>}</td>
                <td><span className="badge">{e.discovered_via}</span></td>
                <td className="mono small">{e.source_file}:{e.line_start}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
