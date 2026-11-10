import { useEffect, useState } from "react";
import { Link, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { api, auth } from "./api";
import Login from "./pages/Login";
import Projects from "./pages/Projects";
import ProjectPage from "./pages/ProjectPage";
import ScanPage from "./pages/ScanPage";
import FindingPage from "./pages/FindingPage";

function Protected({ children }: { children: JSX.Element }) {
  return auth.get() ? children : <Navigate to="/login" replace />;
}

function HealthBadge() {
  const [h, setH] = useState<{ status: string; llm_provider: string; llm_reachable: boolean | null; zap_configured: boolean } | null>(null);
  useEffect(() => {
    api<typeof h>("/api/health").then(setH).catch(() => setH(null));
  }, []);
  if (!h) return <span className="badge sev-high">API offline</span>;
  return (
    <span className="health" aria-label="System status">
      <span className={`badge ${h.status === "ok" ? "ok" : "sev-medium"}`}>API {h.status}</span>
      <span className="badge">LLM: {h.llm_provider}{h.llm_reachable === false ? " (unreachable)" : ""}</span>
      <span className="badge">ZAP: {h.zap_configured ? "on" : "off"}</span>
    </span>
  );
}

export default function App() {
  const nav = useNavigate();
  const signedIn = !!auth.get();
  return (
    <>
      <a href="#main" className="skip">Skip to content</a>
      <header className="topbar">
        <Link to="/" className="brand">APISentinel</Link>
        <HealthBadge />
        {signedIn && (
          <button className="ghost" onClick={() => { auth.clear(); nav("/login"); }}>Sign out</button>
        )}
      </header>
      <main id="main" className="container">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Protected><Projects /></Protected>} />
          <Route path="/projects/:id" element={<Protected><ProjectPage /></Protected>} />
          <Route path="/scans/:id" element={<Protected><ScanPage /></Protected>} />
          <Route path="/findings/:id" element={<Protected><FindingPage /></Protected>} />
          <Route path="*" element={<p>Page not found. <Link to="/">Back to projects</Link></p>} />
        </Routes>
      </main>
    </>
  );
}
