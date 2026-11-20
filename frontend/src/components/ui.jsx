import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";

// ------------------------------------------------------------------ auth context
export const AuthContext = createContext({ user: null, setUser: () => {}, logout: () => {} });
export const useAuth = () => useContext(AuthContext);

export function useCanWrite() {
  const { user } = useAuth();
  return !!user && (user.role === "admin" || user.role === "analyst");
}

// ------------------------------------------------------------------ data hook
// useApi(path) -> { data, error, loading, reload, setData }. Pass null to skip.
export function useApi(path) {
  const [state, setState] = useState({ data: null, error: null, loading: !!path });
  const seq = useRef(0);
  const load = useCallback(async () => {
    if (!path) return;
    const id = ++seq.current;
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const data = await api(path);
      if (id === seq.current) setState({ data, error: null, loading: false });
    } catch (e) {
      if (id === seq.current) setState((s) => ({ ...s, error: e.message, loading: false }));
    }
  }, [path]);
  useEffect(() => {
    load();
  }, [load]);
  const setData = useCallback((data) => setState((s) => ({ ...s, data })), []);
  return { ...state, reload: load, setData };
}

// ------------------------------------------------------------------ formatting
export function formatDate(value, withSeconds = false) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    ...(withSeconds ? { second: "2-digit" } : {}),
  });
}

export function formatShortDate(value) {
  if (!value) return "";
  // "YYYY-MM-DD" day buckets: show as a calendar day without timezone shifting.
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  const d = m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : new Date(value);
  return d.toLocaleDateString(undefined, { weekday: "short", day: "numeric" });
}

export const label = (s) => (s ? String(s).replace(/_/g, " ") : "—");
export const nvdUrl = (cve) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;

export const SEVERITIES = ["critical", "high", "medium", "low"];
export const ALERT_STATUSES = ["new", "triaged", "investigating", "closed"];
export const VERDICTS = ["pending", "true_positive", "false_positive", "benign", "needs_review"];
export const CASE_STATUSES = ["open", "investigating", "contained", "resolved", "closed"];
export const VULN_STATUSES = ["open", "in_progress", "fixed", "accepted_risk", "false_positive"];
export const CRITICALITIES = ["low", "medium", "high", "critical"];
export const ACTION_TYPES = [
  "isolate_host",
  "block_ip",
  "block_domain",
  "disable_user",
  "reset_password",
  "quarantine_file",
  "kill_process",
  "collect_forensics",
];

export function riskLevel(score) {
  const n = Number(score) || 0;
  if (n >= 80) return "critical";
  if (n >= 60) return "high";
  if (n >= 35) return "medium";
  return "low";
}

// ------------------------------------------------------------------ badges
export function SeverityPill({ severity }) {
  const s = SEVERITIES.includes(severity) ? severity : "none";
  return <span className={`pill sev-${s}`}>{severity || "—"}</span>;
}

export function RiskBadge({ score }) {
  const n = Math.round(Number(score) || 0);
  return (
    <span className={`risk risk-${riskLevel(n)}`} title={`Risk score ${n} / 100`}>
      {n}
    </span>
  );
}

export function VerdictChip({ verdict }) {
  const v = verdict || "pending";
  return <span className={`chip verdict-${v}`}>{label(v)}</span>;
}

export function StatusChip({ status }) {
  return <span className={`chip status-${status || "none"}`}>{label(status)}</span>;
}

export function ReputationBadge({ reputation }) {
  const r = reputation || "unknown";
  return <span className={`chip rep-${r}`}>{r}</span>;
}

export function TacticChips({ tactics }) {
  if (!tactics || !tactics.length) return <span className="muted">—</span>;
  return (
    <span className="tag-list">
      {tactics.map((t) => (
        <span key={t} className="tag">
          {t}
        </span>
      ))}
    </span>
  );
}

export function CaseLinks({ ids }) {
  if (!ids || !ids.length) return <span className="muted">—</span>;
  return (
    <span className="tag-list">
      {ids.map((id) => (
        <Link key={id} to={`/cases/${id}`} className="case-link">
          Case #{id}
        </Link>
      ))}
    </span>
  );
}

// ------------------------------------------------------------------ layout pieces
export function Card({ title, actions, children, className = "", id }) {
  return (
    <section className={`card ${className}`} aria-labelledby={title && id ? id : undefined}>
      {(title || actions) && (
        <header className="card-head">
          {title && <h2 id={id}>{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}

export function KpiTile({ label: text, value, sub, tone = "", to }) {
  const inner = (
    <>
      <div className="kpi-label">{text}</div>
      <div className="kpi-value">{value ?? "—"}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </>
  );
  return to ? (
    <Link to={to} className={`kpi ${tone}`}>
      {inner}
    </Link>
  ) : (
    <div className={`kpi ${tone}`}>{inner}</div>
  );
}

export function Spinner({ small }) {
  return <span className={`spinner ${small ? "spinner-sm" : ""}`} aria-hidden="true" />;
}

export function Loading({ text = "Loading…" }) {
  return (
    <div className="loading" role="status" aria-live="polite">
      <Spinner /> <span>{text}</span>
    </div>
  );
}

export function ErrorBox({ error, onRetry }) {
  if (!error) return null;
  return (
    <div className="error-box" role="alert">
      <span>{error}</span>
      {onRetry && (
        <button type="button" className="btn btn-sm" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Notice({ children, tone = "info" }) {
  return (
    <div className={`notice notice-${tone}`} role="status">
      {children}
    </div>
  );
}

export function Empty({ children = "Nothing to show." }) {
  return <p className="empty">{children}</p>;
}

export function TableWrap({ children, label: aria }) {
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label={aria || "Table"}>
      {children}
    </div>
  );
}

// Select bound to a list of options; shows a visible or aria label.
export function Select({ label: text, value, onChange, options, disabled, hideLabel, id, allLabel, className = "" }) {
  const sid = id || `sel-${text.replace(/\W+/g, "-").toLowerCase()}`;
  return (
    <div className={`field ${className}`}>
      <label htmlFor={sid} className={hideLabel ? "sr-only" : ""}>
        {text}
      </label>
      <select id={sid} value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled}>
        {allLabel !== undefined && <option value="">{allLabel}</option>}
        {options.map((o) => {
          const v = typeof o === "string" ? o : o.value;
          const l = typeof o === "string" ? label(o) : o.label;
          return (
            <option key={v} value={v}>
              {l}
            </option>
          );
        })}
      </select>
    </div>
  );
}

export function Button({ busy, children, className = "", disabled, ...rest }) {
  return (
    <button type="button" className={`btn ${className}`} {...rest} disabled={!!(busy || disabled)}>
      {busy && <Spinner small />}
      <span>{children}</span>
    </button>
  );
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {subtitle && <p className="page-sub">{subtitle}</p>}
      </div>
      {children && <div className="page-head-actions">{children}</div>}
    </div>
  );
}

export function Bar({ value, max, tone = "accent", labelText }) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  return (
    <div className="bar" role="img" aria-label={labelText || `${value} of ${max}`}>
      <div className={`bar-fill tone-${tone}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

// AI report (shared by alerts and cases)
export function AiReport({ report, actionsSlot }) {
  if (!report) return <Empty>No AI analysis yet.</Empty>;
  return (
    <div className="ai-report">
      {report.engine_note && <Notice tone="warn">{report.engine_note}</Notice>}
      <div className="ai-meta">
        <VerdictChip verdict={report.verdict} />
        {typeof report.confidence === "number" && (
          <span className="meta-item">
            Confidence <strong>{report.confidence}%</strong>
          </span>
        )}
        {report.severity && (
          <span className="meta-item">
            Assessed severity <SeverityPill severity={report.severity} />
          </span>
        )}
        {report.engine && <span className="chip engine-chip">engine: {report.engine}</span>}
      </div>
      {report.summary && <p className="ai-summary">{report.summary}</p>}
      {report.attack_narrative && (
        <>
          <h3>Attack narrative</h3>
          <p className="prewrap">{report.attack_narrative}</p>
        </>
      )}
      <ListSection title="Key findings" items={report.key_findings} />
      {actionsSlot !== undefined
        ? actionsSlot
        : report.recommended_actions &&
          report.recommended_actions.length > 0 && (
            <>
              <h3>Recommended actions</h3>
              <ul className="action-list">
                {report.recommended_actions.map((a, i) => (
                  <li key={i}>
                    <span className={`chip prio-${a.priority || "normal"}`}>{a.priority || "normal"}</span>{" "}
                    <strong>{label(a.action)}</strong> <code>{a.target}</code>
                    {a.reason && <div className="muted small">{a.reason}</div>}
                  </li>
                ))}
              </ul>
            </>
          )}
      {report.iocs_to_block && report.iocs_to_block.length > 0 && (
        <>
          <h3>IOCs to block</h3>
          <div className="tag-list">
            {report.iocs_to_block.map((i) => (
              <code key={i} className="ioc-code">
                {i}
              </code>
            ))}
          </div>
        </>
      )}
      <ListSection title="Open questions" items={report.open_questions} />
      {report.playbooks && report.playbooks.length > 0 && (
        <>
          <h3>Playbooks</h3>
          <div className="tag-list">
            {report.playbooks.map((p) => (
              <Link key={p} to="/knowledge" className="tag tag-link">
                {p}
              </Link>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function ListSection({ title, items }) {
  if (!items || !items.length) return null;
  return (
    <>
      <h3>{title}</h3>
      <ul className="bullets">
        {items.map((x, i) => (
          <li key={i}>{x}</li>
        ))}
      </ul>
    </>
  );
}
