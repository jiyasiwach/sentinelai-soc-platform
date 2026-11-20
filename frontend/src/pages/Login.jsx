import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { login } from "../api.js";
import { Spinner, useAuth } from "../components/ui.jsx";

const DEMO = [
  { username: "admin", password: "Admin@12345", role: "admin" },
  { username: "analyst", password: "Analyst@12345", role: "analyst" },
  { username: "viewer", password: "Viewer@12345", role: "viewer" },
];

export default function Login() {
  const { setUser } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    if (!username.trim() || !password) {
      setError("Enter your username and password.");
      return;
    }
    setBusy(true);
    try {
      const user = await login(username.trim(), password);
      setUser(user);
      const from = location.state && location.state.from;
      navigate(from && from !== "/login" ? from : "/", { replace: true });
    } catch (err) {
      setError(err.message || "Sign-in failed");
      setBusy(false);
    }
  };

  const fill = (d) => {
    setUsername(d.username);
    setPassword(d.password);
    setError("");
  };

  return (
    <div className="login-page">
      <main className="login-card">
        <div className="brand login-brand">
          <img src="/favicon.svg" alt="" width="40" height="40" />
          <div>
            <h1 className="brand-name">SentinelAI</h1>
            <div className="brand-sub">AI-Powered SOC Investigation Platform</div>
          </div>
        </div>
        <form onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="login-user">Username</label>
            <input
              id="login-user"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
            />
          </div>
          <div className="field">
            <label htmlFor="login-pass">Password</label>
            <input
              id="login-pass"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {error && (
            <div className="error-box" role="alert">
              {error}
            </div>
          )}
          <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
            {busy && <Spinner small />}
            <span>{busy ? "Signing in…" : "Sign in"}</span>
          </button>
        </form>
        <div className="demo-logins">
          <h2>Demo logins</h2>
          <ul>
            {DEMO.map((d) => (
              <li key={d.username}>
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => fill(d)}>
                  Use {d.role}
                </button>
                <code>{d.username}</code> / <code>{d.password}</code>
              </li>
            ))}
          </ul>
        </div>
      </main>
    </div>
  );
}
