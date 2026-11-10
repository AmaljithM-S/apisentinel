import { FormEvent, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, Project } from "../api";

export default function Projects() {
  const nav = useNavigate();
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [error, setError] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [rules, setRules] = useState("");

  useEffect(() => {
    api<Project[]>("/api/projects").then(setProjects).catch((e) => setError(e.message));
  }, []);

  async function create(e: FormEvent) {
    e.preventDefault();
    try {
      const p = await api<Project>("/api/projects", {
        method: "POST",
        body: JSON.stringify({ name, description: description || null, business_rules: rules || null }),
      });
      nav(`/projects/${p.id}`);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <div className="grid2">
      <section>
        <h1>Projects</h1>
        {error && <p role="alert" className="error">{error}</p>}
        {!projects ? <p className="muted">Loading…</p> : projects.length === 0 ? (
          <p className="muted">No projects yet. Create one to start scanning.</p>
        ) : (
          <ul className="list">
            {projects.map((p) => (
              <li key={p.id} className="card">
                <Link to={`/projects/${p.id}`}><strong>{p.name}</strong></Link>{" "}
                <span className="badge">{p.scan_mode}</span>
                {p.description && <p className="muted">{p.description}</p>}
                {p.runtime_base_url && (
                  <p className="mono small">
                    Target: {p.runtime_base_url}
                    {(p.scan_mode === "url" || p.scan_mode === "hybrid") && (
                      <span className={`badge small ${p.target_authorized ? "ok" : ""}`}>
                        {p.target_authorized ? "authorized" : "not authorized"}
                      </span>
                    )}
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="card">
        <h2>New project</h2>
        <form onSubmit={create} className="stack">
          <label>Name<input required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label>Description<input maxLength={4000} value={description} onChange={(e) => setDescription(e.target.value)} /></label>
          <label>Business rules (one per line — compared against the implementation)
            <textarea rows={6} value={rules} onChange={(e) => setRules(e.target.value)}
              placeholder="Users may only view their own orders.&#10;Only admins may delete accounts." />
          </label>
          <button>Create project</button>
        </form>
      </section>
    </div>
  );
}
