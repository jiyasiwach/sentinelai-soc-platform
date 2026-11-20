import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api.js";
import {
  ALERT_STATUSES,
  AiReport,
  Button,
  Card,
  CaseLinks,
  Empty,
  ErrorBox,
  Loading,
  PageHeader,
  ReputationBadge,
  RiskBadge,
  Select,
  SeverityPill,
  StatusChip,
  TableWrap,
  VERDICTS,
  VerdictChip,
  formatDate,
  nvdUrl,
  useApi,
  useCanWrite,
} from "../components/ui.jsx";

function Field({ name, children }) {
  return (
    <div className="kv">
      <dt>{name}</dt>
      <dd>{children || <span className="muted">—</span>}</dd>
    </div>
  );
}

function AssetPosture({ va }) {
  if (!va) return <Empty>Target host is not in the asset inventory, so there is no VA posture.</Empty>;
  const a = va.asset || {};
  return (
    <div className="stack">
      <dl className="kv-grid">
        <Field name="Asset">{a.hostname || a.ip}</Field>
        <Field name="IP">{a.ip}</Field>
        <Field name="OS">{a.os}</Field>
        <Field name="Owner">{a.owner}</Field>
        <Field name="Criticality">{a.criticality && <SeverityPill severity={a.criticality} />}</Field>
        <Field name="Open vulns">{String(va.open_vulns ?? 0)}</Field>
        <Field name="Max CVSS">{String(va.max_cvss ?? 0)}</Field>
        <Field name="Exploitable">
          <span className={va.exploitable_count ? "text-crit" : ""}>{String(va.exploitable_count ?? 0)}</span>
        </Field>
      </dl>
      {va.top_vulns?.length > 0 && (
        <TableWrap label="Top vulnerabilities on target asset">
          <table>
            <thead>
              <tr>
                <th scope="col">Priority</th>
                <th scope="col">Finding</th>
                <th scope="col">CVE</th>
                <th scope="col">CVSS</th>
                <th scope="col">Exploit</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {va.top_vulns.map((v) => (
                <tr key={v.id}>
                  <td>
                    <RiskBadge score={v.priority_score} />
                  </td>
                  <td>
                    {v.title}
                    {v.port ? <span className="muted small"> · port {v.port}</span> : null}
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
                  <td>
                    {v.cvss} <SeverityPill severity={v.severity} />
                  </td>
                  <td>{v.exploit_available ? <span className="chip exploit">public exploit</span> : "—"}</td>
                  <td>
                    <StatusChip status={v.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <Link to="/vulnerabilities" className="small">
        Open vulnerability management →
      </Link>
    </div>
  );
}

function RelatedAlerts({ id }) {
  const { data, error, loading, reload } = useApi(`/alerts/${id}/related`);
  const items = Array.isArray(data) ? data : data?.items || [];
  if (loading && !data) return <Loading text="Correlating…" />;
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!items.length) return <Empty>No correlated alerts.</Empty>;
  return (
    <TableWrap label="Correlated alerts">
      <table>
        <thead>
          <tr>
            <th scope="col">Risk</th>
            <th scope="col">Alert</th>
            <th scope="col">Severity</th>
            <th scope="col">Why correlated</th>
            <th scope="col">Time</th>
          </tr>
        </thead>
        <tbody>
          {items.map((r) => (
            <tr key={r.id}>
              <td>
                <RiskBadge score={r.risk_score} />
              </td>
              <td>
                <Link to={`/alerts/${r.id}`}>{r.title}</Link>
              </td>
              <td>
                <SeverityPill severity={r.severity} />
              </td>
              <td>
                <span className="tag-list">
                  {(r.reasons || []).map((x) => (
                    <span key={x} className="tag">
                      {x}
                    </span>
                  ))}
                </span>
              </td>
              <td className="nowrap">{formatDate(r.event_time)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

export default function AlertDetail() {
  const { id } = useParams();
  const canWrite = useCanWrite();
  const { data: alert, error, loading, reload, setData } = useApi(`/alerts/${id}`);
  const [busy, setBusy] = useState("");
  const [actionError, setActionError] = useState("");

  if (loading && !alert) return <Loading text="Loading alert…" />;
  if (error && !alert) return <ErrorBox error={error} onRetry={reload} />;
  if (!alert) return null;

  const patch = async (field, value) => {
    setBusy(field);
    setActionError("");
    try {
      setData(await api(`/alerts/${alert.id}`, { method: "PATCH", body: { [field]: value } }));
    } catch (e) {
      setActionError(e.message);
    } finally {
      setBusy("");
    }
  };

  const investigate = async () => {
    setBusy("investigate");
    setActionError("");
    try {
      setData(await api(`/alerts/${alert.id}/investigate`, { method: "POST" }));
    } catch (e) {
      setActionError(e.message);
    } finally {
      setBusy("");
    }
  };

  const enr = alert.enrichment || {};
  const reasons = enr.risk_reasons || [];
  const reasonTotal = reasons.reduce((s, r) => s + (Number(r.points) || 0), 0);

  return (
    <div className="page">
      <p className="crumbs">
        <Link to="/alerts">← Alerts</Link>
      </p>
      <PageHeader title={alert.title} subtitle={`Alert #${alert.id}${alert.external_id ? ` · ${alert.external_id}` : ""} · ${alert.source}`}>
        {canWrite && (
          <Button className="btn-primary" busy={busy === "investigate"} onClick={investigate}>
            {busy === "investigate" ? "Investigating…" : alert.ai_report ? "Re-run AI investigation" : "Investigate with AI"}
          </Button>
        )}
      </PageHeader>

      <Card>
        <div className="detail-head">
          <div className="detail-badges">
            <span className="meta-item">
              Risk <RiskBadge score={alert.risk_score} />
            </span>
            <span className="meta-item">
              Severity <SeverityPill severity={alert.severity} />
            </span>
            {!canWrite && (
              <>
                <span className="meta-item">
                  Status <StatusChip status={alert.status} />
                </span>
                <span className="meta-item">
                  Verdict <VerdictChip verdict={alert.verdict} />
                </span>
              </>
            )}
          </div>
          {canWrite && (
            <div className="row wrap">
              <Select label="Status" value={alert.status} onChange={(v) => patch("status", v)} options={ALERT_STATUSES} disabled={!!busy} id="alert-status" />
              <Select label="Verdict" value={alert.verdict} onChange={(v) => patch("verdict", v)} options={VERDICTS} disabled={!!busy} id="alert-verdict" />
            </div>
          )}
        </div>
        <ErrorBox error={actionError} />
        {alert.description && <p className="prewrap">{alert.description}</p>}
        <dl className="kv-grid">
          <Field name="Host">{alert.host}</Field>
          <Field name="User">{alert.username}</Field>
          <Field name="Source IP">{alert.src_ip && <span className="mono">{alert.src_ip}</span>}</Field>
          <Field name="Destination IP">{alert.dst_ip && <span className="mono">{alert.dst_ip}</span>}</Field>
          <Field name="Category">{alert.category}</Field>
          <Field name="Event time">{formatDate(alert.event_time, true)}</Field>
          <Field name="Ingested">{formatDate(alert.created_at)}</Field>
          <Field name="Cases">
            <CaseLinks ids={alert.case_ids} />
          </Field>
        </dl>
      </Card>

      <div className="grid-2 wide-left">
        <Card title="AI investigation report" className="ai-card">
          {busy === "investigate" ? <Loading text="AI is investigating this alert…" /> : <AiReport report={alert.ai_report} />}
        </Card>
        <div className="stack">
          <Card title="Why this risk score">
            {reasons.length ? (
              <table className="score-table">
                <caption className="sr-only">Risk score contributions</caption>
                <tbody>
                  {reasons.map((r, i) => (
                    <tr key={i}>
                      <td className="pts">+{r.points}</td>
                      <td>{r.reason}</td>
                    </tr>
                  ))}
                </tbody>
                <tfoot>
                  <tr>
                    <td className="pts">{reasonTotal}</td>
                    <td>
                      Total (score capped at 100) → <RiskBadge score={alert.risk_score} />
                    </td>
                  </tr>
                </tfoot>
              </table>
            ) : (
              <Empty>No scoring breakdown recorded.</Empty>
            )}
          </Card>
          <Card title="MITRE ATT&CK">
            {alert.mitre?.length ? (
              <div className="tag-list">
                {alert.mitre.map((t) => (
                  <a
                    key={t.id}
                    href={t.url || `https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="attack-chip"
                    title={t.matched?.length ? `Matched: ${t.matched.join(", ")}` : t.tactic}
                  >
                    <span className="mono">{t.id}</span> {t.name}
                    <span className="attack-tactic">{t.tactic}</span>
                  </a>
                ))}
              </div>
            ) : (
              <Empty>No techniques mapped.</Empty>
            )}
          </Card>
          <Card title="Suggested playbooks">
            {enr.playbooks?.length ? (
              <ul className="plain-list">
                {enr.playbooks.map((p) => (
                  <li key={p.id} className="row-between">
                    <Link to="/knowledge">{p.name}</Link>
                    <span className="muted small">match score {p.score}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>No matching playbooks.</Empty>
            )}
          </Card>
        </div>
      </div>

      <Card title="Indicators & threat intelligence">
        {alert.iocs?.length ? (
          <TableWrap label="Indicators of compromise">
            <table>
              <thead>
                <tr>
                  <th scope="col">Type</th>
                  <th scope="col">Value</th>
                  <th scope="col">Reputation</th>
                  <th scope="col">Score</th>
                  <th scope="col">Tags</th>
                  <th scope="col">Country</th>
                  <th scope="col">ASN</th>
                  <th scope="col">Malware family</th>
                </tr>
              </thead>
              <tbody>
                {alert.iocs.map((i, idx) => (
                  <tr key={`${i.type}-${i.value}-${idx}`}>
                    <td>{i.type}</td>
                    <td className="mono break">
                      {i.value}
                      {i.internal && <span className="chip internal-chip">internal</span>}
                    </td>
                    <td>
                      <ReputationBadge reputation={i.reputation} />
                    </td>
                    <td>{i.score ?? "—"}</td>
                    <td>
                      <span className="tag-list">
                        {(i.tags || []).map((t) => (
                          <span key={t} className="tag">
                            {t}
                          </span>
                        ))}
                      </span>
                    </td>
                    <td>{i.country || "—"}</td>
                    <td>{i.asn || "—"}</td>
                    <td>{i.malware_family || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        ) : (
          <Empty>No indicators extracted.</Empty>
        )}
      </Card>

      <Card title="Target asset — vulnerability posture">
        <AssetPosture va={enr.asset} />
      </Card>

      <Card title="Correlated alerts">
        <RelatedAlerts id={alert.id} />
      </Card>

      <Card title="Raw event">
        <details>
          <summary>Show raw event JSON</summary>
          <pre className="raw">{JSON.stringify(alert.raw, null, 2)}</pre>
        </details>
      </Card>
    </div>
  );
}
