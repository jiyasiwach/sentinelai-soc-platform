import { Link } from "react-router-dom";
import {
  Bar,
  Card,
  Empty,
  ErrorBox,
  KpiTile,
  Loading,
  PageHeader,
  RiskBadge,
  SeverityPill,
  SEVERITIES,
  TableWrap,
  VerdictChip,
  formatDate,
  formatShortDate,
  label,
  useApi,
} from "../components/ui.jsx";

function AlertsChart({ days }) {
  const max = Math.max(1, ...days.map((d) => d.count));
  const W = 420;
  const H = 180;
  const pad = { l: 28, r: 8, t: 12, b: 28 };
  const iw = W - pad.l - pad.r;
  const ih = H - pad.t - pad.b;
  const bw = iw / days.length;
  const ticks = [0, Math.ceil(max / 2), max].filter((v, i, a) => a.indexOf(v) === i);
  const summary = days.map((d) => `${formatShortDate(d.date)}: ${d.count} (${d.high} high/critical)`).join("; ");
  return (
    <figure className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Alerts over the last 7 days. ${summary}`}>
        {ticks.map((t) => {
          const y = pad.t + ih - (t / max) * ih;
          return (
            <g key={t}>
              <line x1={pad.l} x2={W - pad.r} y1={y} y2={y} className="grid-line" />
              <text x={pad.l - 6} y={y + 4} textAnchor="end" className="axis-text">
                {t}
              </text>
            </g>
          );
        })}
        {days.map((d, i) => {
          const x = pad.l + i * bw + bw * 0.18;
          const w = bw * 0.64;
          const hTotal = (d.count / max) * ih;
          const hHigh = (d.high / max) * ih;
          const yBase = pad.t + ih;
          return (
            <g key={d.date}>
              <title>{`${d.date}: ${d.count} alerts, ${d.high} high/critical`}</title>
              <rect x={x} y={yBase - hTotal} width={w} height={hTotal} rx="3" className="bar-total" />
              <rect x={x} y={yBase - hHigh} width={w} height={hHigh} rx="3" className="bar-high" />
              {d.count > 0 && (
                <text x={x + w / 2} y={yBase - hTotal - 4} textAnchor="middle" className="axis-text">
                  {d.count}
                </text>
              )}
              <text x={x + w / 2} y={H - 8} textAnchor="middle" className="axis-text">
                {formatShortDate(d.date)}
              </text>
            </g>
          );
        })}
      </svg>
      <figcaption className="legend">
        <span>
          <i className="swatch swatch-total" /> All alerts
        </span>
        <span>
          <i className="swatch swatch-high" /> High + critical
        </span>
      </figcaption>
    </figure>
  );
}

export default function Dashboard() {
  const { data, error, loading, reload } = useApi("/dashboard");

  if (loading && !data) return <Loading text="Loading dashboard…" />;
  if (error && !data) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return null;

  const k = data.kpis || {};
  const sevMax = Math.max(1, ...SEVERITIES.map((s) => data.by_severity?.[s] || 0));
  const tacticMax = Math.max(1, ...(data.tactics || []).map((t) => t.count));
  const sourceMax = Math.max(1, ...(data.sources || []).map((s) => s.count));

  return (
    <div className="page">
      <PageHeader title="Security Operations Dashboard" subtitle={`AI provider: ${data.ai_provider || "unknown"}`}>
        <button type="button" className="btn btn-sm" onClick={reload} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </PageHeader>
      <ErrorBox error={error} />

      <div className="kpi-grid">
        <KpiTile label="Open alerts" value={k.open_alerts} sub={`${k.total_alerts ?? 0} total`} to="/alerts" />
        <KpiTile label="Critical open" value={k.critical_open} tone="kpi-critical" to="/alerts" />
        <KpiTile label="Open cases" value={k.open_cases} to="/cases" />
        <KpiTile label="MTTR" value={k.mttr_hours == null ? "—" : `${k.mttr_hours} h`} sub="mean time to resolve" />
        <KpiTile
          label="Open vulns"
          value={k.open_vulns}
          sub={`${k.exploitable_vulns ?? 0} exploitable`}
          tone={k.exploitable_vulns ? "kpi-high" : ""}
          to="/vulnerabilities"
        />
        <KpiTile label="True positives" value={k.true_positives} tone="kpi-tp" />
      </div>

      <div className="grid-2">
        <Card title="Alerts — last 7 days">
          {data.alerts_7d?.length ? <AlertsChart days={data.alerts_7d} /> : <Empty />}
        </Card>
        <Card title="Open alerts by severity">
          <ul className="hbars">
            {SEVERITIES.map((s) => (
              <li key={s}>
                <span className="hbar-label">
                  <SeverityPill severity={s} />
                </span>
                <Bar value={data.by_severity?.[s] || 0} max={sevMax} tone={s} labelText={`${s}: ${data.by_severity?.[s] || 0}`} />
                <span className="hbar-val">{data.by_severity?.[s] || 0}</span>
              </li>
            ))}
          </ul>
          <h3 className="sub-head">Verdicts (all alerts)</h3>
          <div className="tag-list">
            {Object.entries(data.by_verdict || {}).map(([v, n]) => (
              <span key={v} className="verdict-count">
                <VerdictChip verdict={v} /> <strong>{n}</strong>
              </span>
            ))}
          </div>
        </Card>
      </div>

      <Card title="Top-risk open alerts">
        {data.top_risk?.length ? (
          <TableWrap label="Top-risk open alerts">
            <table>
              <thead>
                <tr>
                  <th scope="col">Risk</th>
                  <th scope="col">Alert</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Verdict</th>
                  <th scope="col">Host</th>
                  <th scope="col">Time</th>
                </tr>
              </thead>
              <tbody>
                {data.top_risk.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <RiskBadge score={a.risk_score} />
                    </td>
                    <td>
                      <Link to={`/alerts/${a.id}`}>{a.title}</Link>
                    </td>
                    <td>
                      <SeverityPill severity={a.severity} />
                    </td>
                    <td>
                      <VerdictChip verdict={a.verdict} />
                    </td>
                    <td>{a.host || "—"}</td>
                    <td className="nowrap">{formatDate(a.event_time)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        ) : (
          <Empty>No open alerts.</Empty>
        )}
      </Card>

      <div className="grid-2">
        <Card title="Top ATT&CK techniques">
          {data.top_techniques?.length ? (
            <ul className="plain-list">
              {data.top_techniques.map((t) => (
                <li key={t.id} className="row-between">
                  <span>
                    <a href={t.url} target="_blank" rel="noopener noreferrer" className="mono">
                      {t.id}
                    </a>{" "}
                    {t.name}
                    <span className="muted small"> · {t.tactic}</span>
                  </span>
                  <strong>{t.count}</strong>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>No techniques mapped yet.</Empty>
          )}
        </Card>
        <Card title="ATT&CK tactics (alerts per tactic)">
          <ul className="hbars compact">
            {(data.tactics || []).map((t) => (
              <li key={t.tactic}>
                <span className="hbar-label">{t.tactic}</span>
                <Bar value={t.count} max={tacticMax} tone="accent" labelText={`${t.tactic}: ${t.count}`} />
                <span className="hbar-val">{t.count}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Top malicious IOCs">
          {data.top_iocs?.length ? (
            <TableWrap label="Top malicious IOCs">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Indicator</th>
                    <th scope="col">Type</th>
                    <th scope="col">Score</th>
                    <th scope="col">Alerts</th>
                    <th scope="col">Tags</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_iocs.map((i) => (
                    <tr key={i.value}>
                      <td className="mono break">{i.value}</td>
                      <td>{i.type}</td>
                      <td>{i.score}</td>
                      <td>{i.count}</td>
                      <td>
                        <span className="tag-list">
                          {(i.tags || []).map((t) => (
                            <span key={t} className="tag">
                              {t}
                            </span>
                          ))}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          ) : (
            <Empty>No malicious indicators observed.</Empty>
          )}
        </Card>
        <Card title="Alert sources">
          {data.sources?.length ? (
            <ul className="hbars compact">
              {data.sources.map((s) => (
                <li key={s.source}>
                  <span className="hbar-label">{label(s.source)}</span>
                  <Bar value={s.count} max={sourceMax} tone="info" labelText={`${s.source}: ${s.count}`} />
                  <span className="hbar-val">{s.count}</span>
                </li>
              ))}
            </ul>
          ) : (
            <Empty />
          )}
        </Card>
      </div>
    </div>
  );
}
