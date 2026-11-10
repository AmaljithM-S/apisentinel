import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, auth } from "../api";

export default function Login() {
  const nav = useNavigate();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("analyst@apisentinel.local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const res = await api<{ access_token: string }>(`/api/auth/${mode}`, {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      auth.set(res.access_token);
      nav("/");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card narrow">
      <h1>{mode === "login" ? "Sign in" : "Create an account"}</h1>
      <p className="muted">Demo account: analyst@apisentinel.local / apisentinel123</p>
      <form onSubmit={submit} className="stack">
        <label>Email<input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        <label>Password
          <input type="password" required minLength={mode === "register" ? 10 : 1} value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && <p role="alert" className="error">{error}</p>}
        <button disabled={busy}>{busy ? "Please wait…" : mode === "login" ? "Sign in" : "Register"}</button>
      </form>
      <button className="link" onClick={() => setMode(mode === "login" ? "register" : "login")}>
        {mode === "login" ? "Need an account? Register" : "Have an account? Sign in"}
      </button>
    </section>
  );
}
