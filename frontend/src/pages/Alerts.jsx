import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, qs } from "../api.js";
import {
  ALERT_STATUSES,
  Button,
  Card,
  CaseLinks,
  Empty,
  ErrorBox,
  Loading,
  Notice,
  PageHeader,
  RiskBadge,
  SEVERITIES,
  Select,
  SeverityPill,
  StatusChip,
  TableWrap,
  TacticChips,
  VERDICTS,
  VerdictChip,
  formatDate,
  useApi,
  useCanWrite,
} from "../components/ui.jsx";

const PAGE_SIZE = 25;
const SORTS = [
  { value: "risk", label: "Highest risk" },
  { value: "time", label: "Newest" },
  { value: "oldest", label: "Oldest" },
  { value: "severity", label: "Severity" },
];
const FORMATS = ["auto", "generic", "wazuh", "splunk", "elastic"];

function IngestPanel({ onDone }) {
  const [mode, setMode] = useState("paste");
  const [text, setText] = useState("");
  const [file, setFile] = useState(null);
  const [format, setFormat] = useState("auto");
  const [investigate, setInvestigate] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setResult(null);
    let res;
    setBusy(true);
    try {
      if (mode === "paste") {
        let parsed;
        try {
          parsed = JSON.parse(text);
        } catch (err) {
          throw new Error(`Invalid JSON: ${err.message}`);
        }
        const alerts = Array.isArray(parsed) ? parsed : [parsed];
        if (!alerts.length) throw new Error("Paste at least one alert.");
        res = await api("/alerts/ingest", { method: "POST", body: { alerts, format, investigate } });
      } else {
        if (!file) throw new Error("Choose a .json or .jsonl file to upload.");
        const form = new FormData();
        form.append("file", file);
        form.append("format", format);
        form.append("investigate", investigate ? "true" : "false");
        res = await api("/alerts/upload", { method: "POST", form });
      }
      setResult(res);
      onDone();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Ingest alerts">
      <form onSubmit={submit} className="stack">
        <div className="segmented" role="radiogroup" aria-label="Ingest method">
          <label className={mode === "paste" ? "on" : ""}>
            <input type="radio" name="ingest-mode" value="paste" checked={mode === "paste"} onChange={() => setMode("paste")} />
            Paste JSON
          </label>
          <label className={mode === "file" ? "on" : ""}>
            <input type="radio" name="ingest-mode" value="file" checked={mode === "file"} onChange={() => setMode("file")} />
            Upload file
          </label>
        </div>
        {mode === "paste" ? (
          <div className="field">
            <label htmlFor="ingest-json">Alert JSON (array or single object)</label>
            <textarea
              id="ingest-json"
              rows={7}
              className="mono"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder='[{"title": "Suspicious login", "severity": "high", "host": "web-01", "src_ip": "198.51.100.77"}]'
            />
          </div>
        ) : (
          <div className="field">
            <label htmlFor="ingest-file">Alert file (.json or .jsonl)</label>
            <input
              id="ingest-file"
              type="file"
              accept=".json,.jsonl,.ndjson,application/json"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
          </div>
        )}
        <div className="row wrap">
          <Select label="Format" value={format} onChange={setFormat} options={FORMATS} id="ingest-format" />
          <label className="check">
            <input type="checkbox" checked={investigate} onChange={(e) => setInvestigate(e.target.checked)} />
            Run AI triage
          </label>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? "Ingesting…" : "Ingest"}
          </button>
        </div>
        <ErrorBox error={error} />
        {result && (
          <Notice tone={result.errors?.length ? "warn" : "ok"}>
            Ingested <strong>{result.ingested}</strong> alert(s)
            {result.errors?.length ? `, ${result.errors.length} error(s)` : ""}.
            {result.errors?.length > 0 && (
              <ul className="bullets small">
                {result.errors.map((er) => (
                  <li key={er.index}>
                    Item {er.index}: {er.error}
                  </li>
                ))}
              </ul>
            )}
            {result.alerts?.length > 0 && (
              <div className="tag-list">
                {result.alerts.slice(0, 20).map((a) => (
                  <Link key={a.id} to={`/alerts/${a.id}`} className="tag tag-link">
                    #{a.id} {a.title}
                  </Link>
                ))}
              </div>
            )}
          </Notice>
        )}
      </form>
    </Card>
  );
}

export default function Alerts() {
  const canWrite = useCanWrite();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("q") || "");
  const [selected, setSelected] = useState(() => new Set());
  const [caseTitle, setCaseTitle] = useState("");
  const [caseBusy, setCaseBusy] = useState(false);
  const [caseError, setCaseError] = useState("");
  const [showIngest, setShowIngest] = useState(false);

  const filters = {
    severity: params.get("severity") || "",
    status: params.get("status") || "",
    verdict: params.get("verdict") || "",
    host: params.get("host") || "",
    q: params.get("q") || "",
    sort: params.get("sort") || "risk",
  };
  const page = Math.max(0, Number(params.get("page") || 0));
  const path = `/alerts${qs({ ...filters, limit: PAGE_SIZE, offset: page * PAGE_SIZE })}`;
  const { data, error, loading, reload } = useApi(path);

  const setFilter = (key, value) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete("page");
    setParams(next, { replace: true });
  };

  // Debounced free-text search
  useEffect(() => {
    const t = setTimeout(() => {
      if (search !== filters.q) setFilter("q", search.trim());
    }, 350);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  const items = data?.items || [];
  const total = data?.total || 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const allOnPage = items.length > 0 && items.every((a) => selected.has(a.id));

  const toggle = (id) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  const toggleAll = () =>
    setSelected((s) => {
      const n = new Set(s);
      items.forEach((a) => (allOnPage ? n.delete(a.id) : n.add(a.id)));
      return n;
    });

  const selectedTitles = useMemo(
    () => items.filter((a) => selected.has(a.id)).map((a) => a.title),
    [items, selected]
  );

  const createCase = async (e) => {
    e.preventDefault();
    setCaseError("");
    const title = caseTitle.trim() || (selectedTitles[0] ? `Investigation: ${selectedTitles[0]}` : "");
    if (title.length < 3) {
      setCaseError("Enter a case title (at least 3 characters).");
      return;
    }
    setCaseBusy(true);
    try {
      const c = await api("/cases", { method: "POST", body: { title: title.slice(0, 512), alert_ids: [...selected] } });
      navigate(`/cases/${c.id}`);
    } catch (err) {
      setCaseError(err.message);
      setCaseBusy(false);
    }
  };

  const goPage = (p) => {
    const next = new URLSearchParams(params);
    if (p > 0) next.set("page", String(p));
    else next.delete("page");
    setParams(next);
  };

  return (
    <div className="page">
      <PageHeader title="Alerts" subtitle={`${total} alert(s) match the current filters`}>
        {canWrite && (
          <button type="button" className="btn" aria-expanded={showIngest} onClick={() => setShowIngest((s) => !s)}>
            {showIngest ? "Hide ingest" : "Ingest alerts"}
          </button>
        )}
      </PageHeader>

      {canWrite && showIngest && <IngestPanel onDone={reload} />}

      <Card>
        <div className="filters">
          <div className="field grow">
            <label htmlFor="alert-search">Search</label>
            <input
              id="alert-search"
              type="search"
              placeholder="Title, host, user, IP…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="alert-host">Host</label>
            <input id="alert-host" value={filters.host} onChange={(e) => setFilter("host", e.target.value)} placeholder="any" />
          </div>
          <Select label="Severity" value={filters.severity} onChange={(v) => setFilter("severity", v)} options={SEVERITIES} allLabel="All" id="f-sev" />
          <Select label="Status" value={filters.status} onChange={(v) => setFilter("status", v)} options={ALERT_STATUSES} allLabel="All" id="f-status" />
          <Select label="Verdict" value={filters.verdict} onChange={(v) => setFilter("verdict", v)} options={VERDICTS} allLabel="All" id="f-verdict" />
          <Select label="Sort" value={filters.sort} onChange={(v) => setFilter("sort", v)} options={SORTS} id="f-sort" />
        </div>

        {canWrite && selected.size > 0 && (
          <form className="selection-bar" onSubmit={createCase}>
            <span>
              <strong>{selected.size}</strong> selected
            </span>
            <div className="field grow">
              <label htmlFor="case-title" className="sr-only">
                New case title
              </label>
              <input
                id="case-title"
                value={caseTitle}
                onChange={(e) => setCaseTitle(e.target.value)}
                placeholder={selectedTitles[0] ? `Investigation: ${selectedTitles[0]}` : "Case title"}
              />
            </div>
            <button type="submit" className="btn btn-primary" disabled={caseBusy}>
              {caseBusy ? "Creating…" : "Create case"}
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => setSelected(new Set())}>
              Clear selection
            </button>
            <ErrorBox error={caseError} />
          </form>
        )}

        <ErrorBox error={error} onRetry={reload} />
        {loading && !data ? (
          <Loading text="Loading alerts…" />
        ) : items.length === 0 ? (
          <Empty>No alerts match these filters.</Empty>
        ) : (
          <TableWrap label="Alerts">
            <table className={loading ? "is-loading" : ""}>
              <thead>
                <tr>
                  {canWrite && (
                    <th scope="col" className="col-check">
                      <input type="checkbox" aria-label="Select all alerts on this page" checked={allOnPage} onChange={toggleAll} />
                    </th>
                  )}
                  <th scope="col">Risk</th>
                  <th scope="col">Alert</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Status</th>
                  <th scope="col">Verdict</th>
                  <th scope="col">Host / user</th>
                  <th scope="col">Tactics</th>
                  <th scope="col">Case</th>
                  <th scope="col">Event time</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.id} className={selected.has(a.id) ? "row-selected" : ""}>
                    {canWrite && (
                      <td className="col-check">
                        <input
                          type="checkbox"
                          aria-label={`Select alert ${a.id}: ${a.title}`}
                          checked={selected.has(a.id)}
                          onChange={() => toggle(a.id)}
                        />
                      </td>
                    )}
                    <td>
                      <RiskBadge score={a.risk_score} />
                    </td>
                    <td className="col-title">
                      <Link to={`/alerts/${a.id}`}>{a.title}</Link>
                      <div className="muted small">
                        #{a.id} · {a.source}
                        {a.malicious_iocs > 0 && <span className="text-crit"> · {a.malicious_iocs} malicious IOC</span>}
                      </div>
                    </td>
                    <td>
                      <SeverityPill severity={a.severity} />
                    </td>
                    <td>
                      <StatusChip status={a.status} />
                    </td>
                    <td>
                      <VerdictChip verdict={a.verdict} />
                    </td>
                    <td>
                      <div>{a.host || "—"}</div>
                      <div className="muted small">{a.username}</div>
                    </td>
                    <td>
                      <TacticChips tactics={a.tactics} />
                    </td>
                    <td>
                      <CaseLinks ids={a.case_ids} />
                    </td>
                    <td className="nowrap">{formatDate(a.event_time)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
        <nav className="pager" aria-label="Alert pages">
          <Button className="btn-sm" onClick={() => goPage(page - 1)} disabled={page <= 0 || loading}>
            Previous
          </Button>
          <span>
            Page {Math.min(page + 1, pages)} of {pages}
          </span>
          <Button className="btn-sm" onClick={() => goPage(page + 1)} disabled={page + 1 >= pages || loading}>
            Next
          </Button>
        </nav>
      </Card>
    </div>
  );
}
