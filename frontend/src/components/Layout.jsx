import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api.js";
import { useAuth } from "./ui.jsx";

const NAV = [
  { to: "/", label: "Dashboard", icon: "M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z", end: true },
  { to: "/alerts", label: "Alerts", icon: "M12 2 1 21h22L12 2zm1 15h-2v-2h2v2zm0-4h-2V9h2v4z" },
  { to: "/cases", label: "Cases", icon: "M10 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-8l-2-2z" },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: "M12 1 3 5v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V5l-9-4zm-1 6h2v6h-2V7zm0 8h2v2h-2v-2z" },
  { to: "/knowledge", label: "ATT&CK & Playbooks", icon: "M4 6h16v2H4V6zm0 5h16v2H4v-2zm0 5h10v2H4v-2z" },
  { to: "/admin", label: "Admin", icon: "M12 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10zm0 2c-5 0-9 2.5-9 5v3h18v-3c0-2.5-4-5-9-5z", admin: true },
];

function Icon({ d }) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false">
      <path d={d} fill="currentColor" />
    </svg>
  );
}

export default function Layout() {
  const { user, logout } = useAuth();
  const [provider, setProvider] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    let alive = true;
    api("/health")
      .then((h) => alive && setProvider(h.ai_provider || ""))
      .catch(() => alive && setProvider(""));
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  const doLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  const items = NAV.filter((n) => !n.admin || (user && user.role === "admin"));

  return (
    <div className="shell">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <aside className={`sidebar ${menuOpen ? "open" : ""}`}>
        <div className="brand-row">
          <div className="brand">
            <img src="/favicon.svg" alt="" width="28" height="28" />
            <div>
              <div className="brand-name">SentinelAI</div>
              <div className="brand-sub">SOC Investigation</div>
            </div>
          </div>
          <button
            type="button"
            className="btn btn-ghost menu-toggle"
            aria-expanded={menuOpen}
            aria-controls="main-nav"
            onClick={() => setMenuOpen((o) => !o)}
          >
            {menuOpen ? "Close" : "Menu"}
          </button>
        </div>
        <nav id="main-nav" aria-label="Main navigation">
          <ul>
            {items.map((n) => (
              <li key={n.to}>
                <NavLink to={n.to} end={n.end} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
                  <Icon d={n.icon} />
                  <span>{n.label}</span>
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="sidebar-foot">
          <div className="provider" title="AI provider configured on the backend">
            <span className={`dot ${provider ? "dot-on" : ""}`} aria-hidden="true" />
            AI provider: <strong>{provider || "unknown"}</strong>
          </div>
        </div>
      </aside>
      <div className="main-col">
        <header className="topbar">
          <div className="topbar-provider">
            AI: <strong>{provider || "…"}</strong>
          </div>
          <div className="user-box">
            <span className="user-name">{user?.full_name || user?.username}</span>
            <span className={`chip role-${user?.role}`}>{user?.role}</span>
            <button type="button" className="btn btn-sm" onClick={doLogout}>
              Log out
            </button>
          </div>
        </header>
        <main id="main" className="content" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
