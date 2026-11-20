import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, qs } from "../api.js";
import {
  Bar,
  Button,
  CRITICALITIES,
  Card,
  Empty,
  ErrorBox,
  Loading,
  Notice,
  PageHeader,
  SEVERITIES,
  Select,
  SeverityPill,
  StatusChip,
  TableWrap,
  VULN_STATUSES,
  formatDate,
  label,
  nvdUrl,
  riskLevel,
  useApi,
  useCanWrite,
} from "../components/ui.jsx";

const TABS = [
  { id: "findings", label: "Findings" },
  { id: "assets", label: "Assets" },
  { id: "import", label: "Import" },
];

function Findings({ canWrite }) {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const { data, error, loading, reload, setData } = useApi(`/va/vulnerabilities${qs({ severity, status })}`);
  const [rowBusy, setRowBusy] = useState(null);
  const [rowError, setRowError] = useState("");

  const updateStatus = async (v, next) => {
    setRowBusy(v.id);
    setRowError("");
    try {
      const updated = await api(`/va/vulnerabilities/${v.id}`, { method: "PATCH", body: { status: next } });
      setData((data || []).map((x) => (x.id === updated.id ? updated : x)));
    } catch (e) {
      setRowError(e.message);
    } finally {
      setRowBusy(null);
    }
  };

  const rows = data || [];
  return (
    <Card>
      <div className="filters">
        <Select label="Severity" value={severity} onChange={setSeverity} options={SEVERITIES} allLabel="All" id="v-sev" />
        <Select label="Status" value={status} onChange={setStatus} options={VULN_STATUSES} allLabel="All" id="v-status" />
        <span className="muted small filters-note">{rows.length} finding(s), highest priority first</span>
      </div>
      <ErrorBox error={error} onRetry={reload} />
      <ErrorBox error={rowError} />
      {loading && !data ? (
        <Loading text="Loading findings…" />
      ) : rows.length === 0 ? (
        <Empty>No findings match.</Empty>
      ) : (
        <TableWrap label="Vulnerability findings">
          <table>
            <thead>
              <tr>
                <th scope="col">Priority</th>
                <th scope="col">Finding</th>
                <th scope="col">Asset</th>
                <th scope="col">CVE</th>
                <th scope="col">CVSS</th>
                <th scope="col">Exploit</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((v) => (
                <tr key={v.id}>
                  <td className="col-priority">
                    <div className="prio-cell" title={v.priority_explained}>
                      <strong>{v.priority_score}</strong>
                      <Bar value={v.priority_score} max={100} tone={riskLevel(v.priority_score)} labelText={`Priority ${v.priority_score} of 100`} />
                    </div>
                    <div className="muted tiny">{v.priority_explained}</div>
                  </td>
                  <td className="col-title">
                    <div>{v.title}</div>
                    <div className="muted small">
                      {v.port ? `port ${v.port}` : ""}
                      {v.service ? ` · ${v.service}` : ""} · source {v.source} · first seen {formatDate(v.first_seen)}
                    </div>
                    {(v.description || v.remediation) && (
                      <details className="small">
                        <summary>Details & remediation</summary>
                        {v.description && <p>{v.description}</p>}
                        {v.remediation && (
                          <p>
                            <strong>Fix:</strong> {v.remediation}
                          </p>
                        )}
                      </details>
                    )}
                  </td>
                  <td>
                    <div>{v.asset || "—"}</div>
                    {v.asset_criticality && <div className="muted small">{v.asset_criticality} criticality</div>}
                  </td>
                  <td className="nowrap">
                    {v.cve ? (
                      <a href={nvdUrl(v.cve)} target="_blank" rel="noopener noreferrer" className="mono">
                        {v.cve}
                      </a>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="nowrap">
                    {v.cvss} <SeverityPill severity={v.severity} />
                  </td>
                  <td>{v.exploit_available ? <span className="chip exploit">public exploit</span> : <span className="muted">—</span>}</td>
                  <td>
                    {canWrite ? (
                      <Select
                        label={`Status for finding ${v.id}`}
                        hideLabel
                        value={v.status}
                        onChange={(next) => updateStatus(v, next)}
                        options={VULN_STATUSES}
                        disabled={rowBusy === v.id}
                        id={`vstatus-${v.id}`}
                      />
                    ) : (
                      <StatusChip status={v.status} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Card>
  );
}

function Assets({ canWrite }) {
  const { data, error, loading, reload, setData } = useApi("/va/assets");
  const [rowBusy, setRowBusy] = useState(null);
  const [rowError, setRowError] = useState("");
  const [notice, setNotice] = useState("");

  const updateCriticality = async (a, criticality) => {
    setRowBusy(a.id);
    setRowError("");
    setNotice("");
    try {
      const updated = await api(`/va/assets/${a.id}`, { method: "PATCH", body: { criticality } });
      setData((data || []).map((x) => (x.id === updated.id ? updated : x)));
      setNotice(`${updated.hostname || updated.ip} is now ${criticality} criticality — its findings were re-prioritised.`);
    } catch (e) {
      setRowError(e.message);
    } finally {
      setRowBusy(null);
    }
  };

  const rows = data || [];
  return (
    <Card>
      <p className="muted small">Changing an asset's criticality re-prioritises every finding on that asset.</p>
      {notice && <Notice tone="ok">{notice}</Notice>}
      <ErrorBox error={error} onRetry={reload} />
      <ErrorBox error={rowError} />
      {loading && !data ? (
        <Loading text="Loading assets…" />
      ) : rows.length === 0 ? (
        <Empty>No assets yet. Import an Nmap scan to build the inventory.</Empty>
      ) : (
        <TableWrap label="Assets">
          <table>
            <thead>
              <tr>
                <th scope="col">Hostname</th>
                <th scope="col">IP</th>
                <th scope="col">OS</th>
                <th scope="col">Owner</th>
                <th scope="col">Open ports</th>
                <th scope="col">Open vulns</th>
                <th scope="col">Max CVSS</th>
                <th scope="col">Criticality</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id}>
                  <td>
                    <strong>{a.hostname || "—"}</strong>
                    <div className="muted small">scanned {formatDate(a.last_scanned)}</div>
                  </td>
                  <td className="mono">{a.ip || "—"}</td>
                  <td>{a.os || "—"}</td>
                  <td>{a.owner || "—"}</td>
                  <td>
                    <span className="tag-list">
                      {(a.open_ports || []).map((p) => (
                        <span key={`${p.port}/${p.protocol}`} className="tag" title={p.product || p.service}>
                          {p.port}/{p.protocol}
                          {p.service ? ` ${p.service}` : ""}
                        </span>
                      ))}
                      {!a.open_ports?.length && <span className="muted">—</span>}
                    </span>
                  </td>
                  <td>
                    {a.open_vulns}
                    {a.exploitable > 0 && <span className="chip exploit">{a.exploitable} exploitable</span>}
                  </td>
                  <td>{a.max_cvss}</td>
                  <td>
                    {canWrite ? (
                      <Select
                        label={`Criticality for ${a.hostname || a.ip}`}
                        hideLabel
                        value={a.criticality}
                        onChange={(c) => updateCriticality(a, c)}
                        options={CRITICALITIES}
                        disabled={rowBusy === a.id}
                        id={`crit-${a.id}`}
                      />
                    ) : (
                      <SeverityPill severity={a.criticality} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Card>
  );
}

function Summary({ result }) {
  if (!result) return null;
  return (
    <Notice tone="ok">
      Import complete:{" "}
      {Object.entries(result)
        .map(([k, v]) => `${label(k)}: ${v}`)
        .join(" · ")}
    </Notice>
  );
}

function ImportTab() {
  const [nmapFile, setNmapFile] = useState(null);
  const [nmapBusy, setNmapBusy] = useState(false);
  const [nmapError, setNmapError] = useState("");
  const [nmapResult, setNmapResult] = useState(null);

  const [json, setJson] = useState("");
  const [jsonFile, setJsonFile] = useState(null);
  const [fBusy, setFBusy] = useState(false);
  const [fError, setFError] = useState("");
  const [fResult, setFResult] = useState(null);

  const importNmap = async (e) => {
    e.preventDefault();
    setNmapError("");
    setNmapResult(null);
    if (!nmapFile) {
      setNmapError("Choose an Nmap XML file (nmap -oX).");
      return;
    }
    setNmapBusy(true);
    try {
      const form = new FormData();
      form.append("file", nmapFile);
      setNmapResult(await api("/va/import/nmap", { method: "POST", form }));
    } catch (err) {
      setNmapError(err.message);
    } finally {
      setNmapBusy(false);
    }
  };

  const importFindings = async (e) => {
    e.preventDefault();
    setFError("");
    setFResult(null);
    setFBusy(true);
    try {
      const text = jsonFile ? await jsonFile.text() : json;
      if (!text.trim()) throw new Error("Paste findings JSON or choose a file.");
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch (err) {
        throw new Error(`Invalid JSON: ${err.message}`);
      }
      const body = Array.isArray(parsed) ? { findings: parsed } : parsed.findings ? { findings: parsed.findings } : { findings: [parsed] };
      setFResult(await api("/va/vulnerabilities", { method: "POST", body }));
    } catch (err) {
      setFError(err.message);
    } finally {
      setFBusy(false);
    }
  };

  return (
    <div className="grid-2">
      <Card title="Nmap XML scan">
        <form className="stack" onSubmit={importNmap}>
          <p className="muted small">
            Upload the XML output of an authorised scan (<code>nmap -sV -O -oX scan.xml</code>). Hosts become assets and risky open
            services become findings.
          </p>
          <div className="field">
            <label htmlFor="nmap-file">Nmap XML file</label>
            <input id="nmap-file" type="file" accept=".xml,text/xml,application/xml" onChange={(e) => setNmapFile(e.target.files?.[0] || null)} />
          </div>
          <div>
            <Button type="submit" className="btn-primary" busy={nmapBusy}>
              Import scan
            </Button>
          </div>
          <ErrorBox error={nmapError} />
          <Summary result={nmapResult} />
        </form>
      </Card>
      <Card title="Findings JSON (Nessus / OpenVAS / pentest)">
        <form className="stack" onSubmit={importFindings}>
          <p className="muted small">
            An array of findings, or <code>{'{"findings": [...]}'}</code>. Fields: host, title, cve, cvss, port, service, description,
            remediation, exploit_available, source (nmap|nessus|openvas|manual|pentest), ip.
          </p>
          <div className="field">
            <label htmlFor="findings-json">Paste findings JSON</label>
            <textarea
              id="findings-json"
              rows={6}
              className="mono"
              value={json}
              onChange={(e) => setJson(e.target.value)}
              placeholder='[{"host": "web-01", "title": "Outdated OpenSSL", "cve": "CVE-2022-3602", "cvss": 7.5, "source": "nessus"}]'
              disabled={!!jsonFile}
            />
          </div>
          <div className="field">
            <label htmlFor="findings-file">…or choose a JSON file</label>
            <input id="findings-file" type="file" accept=".json,application/json" onChange={(e) => setJsonFile(e.target.files?.[0] || null)} />
          </div>
          <div>
            <Button type="submit" className="btn-primary" busy={fBusy}>
              Import findings
            </Button>
          </div>
          <ErrorBox error={fError} />
          <Summary result={fResult} />
        </form>
      </Card>
    </div>
  );
}

export default function Vulnerabilities() {
  const canWrite = useCanWrite();
  const [params, setParams] = useSearchParams();
  const tabs = canWrite ? TABS : TABS.filter((t) => t.id !== "import");
  const requested = params.get("tab") || "findings";
  const tab = tabs.some((t) => t.id === requested) ? requested : "findings";

  return (
    <div className="page">
      <PageHeader title="Vulnerability management" subtitle="Risk-based prioritisation of findings from authorised scans and tests" />
      <Notice tone="info">
        Priority = min(100, CVSS × 7 × asset-criticality weight (low 0.7, medium 1, high 1.2, critical 1.4) + 12 if a public exploit
        exists + 10 if the asset has open alerts). SentinelAI only analyses the results of authorised tests — it does not scan anything
        itself.
      </Notice>
      <div className="tabs" role="tablist" aria-label="Vulnerability views">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            className={`tab ${tab === t.id ? "active" : ""}`}
            onClick={() => setParams(t.id === "findings" ? {} : { tab: t.id }, { replace: true })}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === "findings" && <Findings canWrite={canWrite} />}
        {tab === "assets" && <Assets canWrite={canWrite} />}
        {tab === "import" && canWrite && <ImportTab />}
      </div>
    </div>
  );
}
