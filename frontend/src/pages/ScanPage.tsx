import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { EvidenceLevel, Finding, Summary, api, download } from "../api";
import { Confidence, SeverityBadge, StatusPill } from "../components/ui";

// Must match the keys services.scan_service._set_layer writes under
// Scan.layer_status, exactly — a mismatch here silently shows every card as
// "pending" forever, which is what happened to "parser" (previously spelled
// "parse" here) before this was fixed.
const LAYERS = ["parser", "static", "llm", "runtime", "risk_engine"];
const SEV_ORDER = ["critical", "high", "medium", "low"];
const EVIDENCE_ORDER: EvidenceLevel[] = ["confirmed", "suspected", "inconclusive"];
const EVIDENCE_LABEL: Record<EvidenceLevel, string> = {
  confirmed: "Confirmed", suspected: "Suspected", inconclusive: "Inconclusive",
};

export default function ScanPage() {
  const { id } = useParams();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState("");
  const [sev, setSev] = useState("");
  const [cat, setCat] = useState("");
  const [st, setSt] = useState("");
  const [ev, setEv] = useState("");

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    let alive = true;
    const tick = async () => {
      try {
        const s = await api<Summary>(`/api/scans/${id}/summary`);
        if (!alive) return;
        setSummary(s);
        setFindings(await api<Finding[]>(`/api/scans/${id}/findings`));
        if (s.scan.status === "running" || s.scan.status === "queued") timer = setTimeout(tick, 3000);
      } catch (e) { if (alive) setError((e as Error).message); }
    };
    tick();
    return () => { alive = false; clearTimeout(timer); };
  }, [id]);

  const shown = useMemo(() => findings
    .filter((f) => (!sev || f.severity === sev) && (!cat || f.owasp_category === cat) && (!st || f.status === st) && (!ev || f.evidence_level === ev))
    .sort((a, b) => b.risk_score - a.risk_score), [findings, sev, cat, st, ev]);

  if (!summary) return error ? <p role="alert" className="error">{error}</p> : <p className="muted">Loading scan…</p>;
  const { scan } = summary;

  return (
    <>
      <p><Link to={`/projects/${scan.project_id}`}>← Project</Link></p>
      <div className="row between">
        <h1>Scan report <StatusPill status={scan.status} /></h1>
        <div className="row">
          {(["json", "md", "sarif"] as const).map((f) => (
            <button key={f} className="ghost" onClick={() => download(`/api/scans/${id}/report.${f}`, `apisentinel-${id}.${f}`).catch((e) => setError(e.message))}>
              Export {f.toUpperCase()}
            </button>
          ))}
        </div>
      </div>
      {error && <p role="alert" className="error">{error}</p>}
      {scan.error && <p role="alert" className="error">{scan.error}</p>}

      <section className="layers" aria-label="Layer progress">
        {LAYERS.map((l) => {
          const s = scan.layer_status?.[l];
          return (
            <div key={l} className="card layer">
              <strong>
                {l === "parser" && s?.source_mode === "url" ? "web discovery" : l.replace("_", " ")}
              </strong>
              <StatusPill status={s?.status ?? "pending"} />
              {s?.endpoints !== undefined && <span className="small">{s.endpoints} endpoints</span>}
              {s?.findings !== undefined && <span className="small">{s.findings} signals</span>}
              {l === "parser" && s?.source_mode && s.source_mode !== "source" && (
                <span className="small muted">
                  {s.pages_visited ?? 0} pages crawled{s.openapi_found ? ", spec found" : ""}
                  {s.js_rendering_used ? `, ${s.js_pages_rendered ?? 0} JS-rendered` : ""}
                </span>
              )}
              {s?.message && <span className="small muted">{s.message}</span>}
            </div>
          );
        })}
      </section>

      <section className="stats">
        <div className="card stat"><span className="big">{summary.total}</span>findings</div>
        {SEV_ORDER.map((s) => (
          <div key={s} className="card stat"><span className={`big sev-${s}-text`}>{summary.by_severity[s] ?? 0}</span>{s}</div>
        ))}
        <div className="card stat"><span className="big">{summary.runtime_confirmed}</span>runtime-confirmed</div>
        <div className="card stat"><span className="big">{Math.round(summary.mean_confidence * 100)}%</span>mean confidence</div>
      </section>

      <section className="card">
        <div className="row">
          <label>Severity<select value={sev} onChange={(e) => setSev(e.target.value)}><option value="">All</option>{SEV_ORDER.map((s) => <option key={s}>{s}</option>)}</select></label>
          <label>OWASP category<select value={cat} onChange={(e) => setCat(e.target.value)}><option value="">All</option>{Object.keys(summary.by_category).sort().map((c) => <option key={c}>{c}</option>)}</select></label>
          <label>Status<select value={st} onChange={(e) => setSt(e.target.value)}><option value="">All</option>{["open", "confirmed", "false_positive", "fixed"].map((s) => <option key={s}>{s}</option>)}</select></label>
          <label>Evidence<select value={ev} onChange={(e) => setEv(e.target.value)}><option value="">All</option>{EVIDENCE_ORDER.map((s) => <option key={s} value={s}>{EVIDENCE_LABEL[s]}</option>)}</select></label>
        </div>
        <table>
          <thead><tr><th>Severity</th><th>Finding</th><th>OWASP</th><th>Endpoint</th><th>Evidence</th><th>Confidence</th><th>Risk</th><th>Status</th></tr></thead>
          <tbody>
            {shown.map((f) => (
              <tr key={f.id}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td><Link to={`/findings/${f.id}`}>{f.title}</Link>{f.needs_manual_review && <span className="badge sev-medium small">review</span>}</td>
                <td title={f.owasp_title}>{f.owasp_category}</td>
                <td className="mono small">{f.method} {f.path}</td>
                <td><span className={`badge ${f.evidence_level === "confirmed" ? "ok" : ""}`}>{EVIDENCE_LABEL[f.evidence_level]}</span></td>
                <td><Confidence value={f.confidence} /></td>
                <td>{f.risk_score.toFixed(2)}</td>
                <td>{f.status}</td>
              </tr>
            ))}
            {shown.length === 0 && <tr><td colSpan={8} className="muted">{scan.status === "running" ? "Scan in progress…" : "No findings match."}</td></tr>}
          </tbody>
        </table>
      </section>
    </>
  );
}
