import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, qs } from "../api.js";
import {
  Button,
  CASE_STATUSES,
  Card,
  Empty,
  ErrorBox,
  Loading,
  Notice,
  PageHeader,
  RiskBadge,
  Select,
  SeverityPill,
  StatusChip,
  TableWrap,
  VerdictChip,
  formatDate,
  useApi,
  useCanWrite,
} from "../components/ui.jsx";

export default function Cases() {
  const canWrite = useCanWrite();
  const [params, setParams] = useSearchParams();
  const status = params.get("status") || "";
  const { data, error, loading, reload } = useApi(`/cases${qs({ status })}`);
  const [busy, setBusy] = useState(false);
  const [groupResult, setGroupResult] = useState(null);
  const [groupError, setGroupError] = useState("");

  const autoGroup = async () => {
    setBusy(true);
    setGroupError("");
    setGroupResult(null);
    try {
      const res = await api("/cases/auto-group", { method: "POST" });
      setGroupResult(res);
      reload();
    } catch (e) {
      setGroupError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const cases = data || [];

  return (
    <div className="page">
      <PageHeader title="Cases" subtitle="Incidents grouping one or more correlated alerts">
        {canWrite && (
          <Button busy={busy} onClick={autoGroup} title="Group correlated, un-cased alerts into new cases">
            {busy ? "Grouping…" : "Auto-group alerts"}
          </Button>
        )}
      </PageHeader>
      <ErrorBox error={groupError} />
      {groupResult && (
        <Notice tone={groupResult.created ? "ok" : "info"}>
          Auto-group created <strong>{groupResult.created}</strong> case(s).
          {groupResult.cases?.length > 0 && (
            <div className="tag-list">
              {groupResult.cases.map((c) => (
                <Link key={c.id} to={`/cases/${c.id}`} className="tag tag-link">
                  #{c.id} {c.title} ({c.alert_count} alerts)
                </Link>
              ))}
            </div>
          )}
        </Notice>
      )}
      <Card>
        <div className="filters">
          <Select
            label="Status"
            value={status}
            onChange={(v) => setParams(v ? { status: v } : {}, { replace: true })}
            options={CASE_STATUSES}
            allLabel="All"
            id="case-status-filter"
          />
        </div>
        <ErrorBox error={error} onRetry={reload} />
        {loading && !data ? (
          <Loading text="Loading cases…" />
        ) : cases.length === 0 ? (
          <Empty>
            No cases{status ? ` with status "${status}"` : ""}. {canWrite ? "Select alerts on the Alerts page or auto-group them." : ""}
          </Empty>
        ) : (
          <TableWrap label="Cases">
            <table>
              <thead>
                <tr>
                  <th scope="col">#</th>
                  <th scope="col">Title</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Status</th>
                  <th scope="col">Max risk</th>
                  <th scope="col">Alerts</th>
                  <th scope="col">AI verdict</th>
                  <th scope="col">Assignee</th>
                  <th scope="col">Updated</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((c) => (
                  <tr key={c.id}>
                    <td>{c.id}</td>
                    <td className="col-title">
                      <Link to={`/cases/${c.id}`}>{c.title}</Link>
                      <div className="muted small">created by {c.created_by} · {formatDate(c.created_at)}</div>
                    </td>
                    <td>
                      <SeverityPill severity={c.severity} />
                    </td>
                    <td>
                      <StatusChip status={c.status} />
                    </td>
                    <td>
                      <RiskBadge score={c.max_risk} />
                    </td>
                    <td>{c.alert_count}</td>
                    <td>{c.verdict ? <VerdictChip verdict={c.verdict} /> : <span className="muted">not analysed</span>}</td>
                    <td>{c.assignee || "—"}</td>
                    <td className="nowrap">{formatDate(c.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>
    </div>
  );
}
