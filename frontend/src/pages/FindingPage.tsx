import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, FindingDetail } from "../api";
import { Confidence, SeverityBadge } from "../components/ui";

const STATUSES = [
  ["open", "Open"], ["confirmed", "Confirmed"], ["false_positive", "False positive"], ["fixed", "Fixed"],
] as const;

export default function FindingPage() {
  const { id } = useParams();
  const [f, setF] = useState<FindingDetail | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => { api<FindingDetail>(`/api/findings/${id}`).then(setF).catch((e) => setError(e.message)); }, [id]);

  async function setStatus(status: string) {
    setBusy(true); setError("");
    try { setF(await api<FindingDetail>(`/api/findings/${id}/status`, { method: "PATCH", body: JSON.stringify({ status }) })); }
    catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }

  async function verify() {
    setBusy(true); setError(""); setNotice("");
    try {
      await api(`/api/findings/${id}/verify`, { method: "POST", body: JSON.stringify({}) });
      setF(await api<FindingDetail>(`/api/findings/${id}`));
      setNotice("Runtime re-verification finished.");
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }

  if (!f) return error ? <p role="alert" className="error">{error}</p> : <p className="muted">Loading…</p>;

  return (
    <>
      <p><Link to={`/scans/${f.scan_id}`}>← Scan report</Link></p>
      <h1><SeverityBadge severity={f.severity} /> {f.title}</h1>
      <p className="row">
        <span className={`badge ${f.evidence_level === "confirmed" ? "ok" : ""}`}>
          {f.evidence_level === "confirmed" ? "Confirmed" : f.evidence_level === "suspected" ? "Suspected" : "Inconclusive"}
        </span>
        <span className="badge">{f.owasp_category} · {f.owasp_title}</span>
        {f.cwe && <span className="badge">{f.cwe}</span>}
        {f.stride?.map((s) => <span key={s} className="badge">STRIDE: {s}</span>)}
        <Confidence value={f.confidence} />
        <span>Risk {f.risk_score.toFixed(2)}</span>
      </p>
      <p className="mono small">{f.method} {f.path} — {f.source_file}{f.line_start ? `:${f.line_start}` : ""}</p>
      {error && <p role="alert" className="error">{error}</p>}
      {notice && <p role="status" className="notice">{notice}</p>}

      <section className="card">
        <h2>Analyst review</h2>
        <div className="row" role="group" aria-label="Set finding status">
          {STATUSES.map(([v, label]) => (
            <button key={v} className={f.status === v ? "" : "ghost"} aria-pressed={f.status === v} disabled={busy} onClick={() => setStatus(v)}>{label}</button>
          ))}
          <button className="ghost" disabled={busy} onClick={verify}>Re-verify at runtime</button>
        </div>
        {f.needs_manual_review && <p className="muted small">Flagged for manual review: only one layer reported this and it was not confirmed at runtime.</p>}
      </section>

      <section className="card"><h2>Description</h2><p className="pre">{f.description}</p>
        {f.business_rule_ref && <p><strong>Business rule:</strong> {f.business_rule_ref}</p>}
      </section>

      <section className="card">
        <h2>Evidence ({f.evidence.length})</h2>
        <table>
          <thead><tr><th>Layer</th><th>Tool</th><th>Confidence</th><th>Summary</th></tr></thead>
          <tbody>{f.evidence.map((e) => (
            <tr key={e.id}><td>{e.source}</td><td className="mono small">{e.tool}</td><td><Confidence value={e.confidence} /></td><td>{e.summary}</td></tr>
          ))}</tbody>
        </table>
      </section>

      {f.runtime_tests.length > 0 && (
        <section className="card">
          <h2>Runtime tests</h2>
          <table>
            <thead><tr><th>Test</th><th>Target</th><th>Outcome</th></tr></thead>
            <tbody>{f.runtime_tests.map((t) => (
              <tr key={t.id}><td>{t.name}</td><td className="mono small">{t.target_url}</td><td>{t.confirmed ? <strong className="sev-critical-text">confirmed</strong> : t.outcome}</td></tr>
            ))}</tbody>
          </table>
        </section>
      )}

      <section className="card">
        <h2>Remediation</h2>
        {f.remediation && <p className="pre">{f.remediation}</p>}
        {f.remediation_code && <pre className="code"><code>{f.remediation_code}</code></pre>}
      </section>
    </>
  );
}
