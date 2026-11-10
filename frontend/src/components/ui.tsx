export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

export function StatusPill({ status }: { status: string }) {
  const cls = status === "completed" || status === "ok" ? "ok" : status === "failed" ? "sev-high" : status === "degraded" ? "sev-medium" : "";
  return <span className={`badge ${cls}`}>{status}</span>;
}

export function Confidence({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  return (
    <span className="conf" title={`${pct}% confidence`}>
      <span className="bar" role="meter" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Confidence">
        <span style={{ width: `${pct}%` }} />
      </span>
      {pct}%
    </span>
  );
}
