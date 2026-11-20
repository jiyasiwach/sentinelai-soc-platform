import { useMemo, useState } from "react";
import { Card, Empty, ErrorBox, Loading, PageHeader, useApi } from "../components/ui.jsx";

function Matrix({ data }) {
  const [onlyHits, setOnlyHits] = useState(false);
  const byTactic = useMemo(() => {
    const m = {};
    (data.tactics || []).forEach((t) => (m[t] = []));
    (data.techniques || []).forEach((t) => {
      (m[t.tactic] = m[t.tactic] || []).push(t);
    });
    Object.values(m).forEach((list) => list.sort((a, b) => b.alert_count - a.alert_count || a.id.localeCompare(b.id)));
    return m;
  }, [data]);
  const tactics = Object.keys(byTactic);
  const covered = (data.techniques || []).filter((t) => t.alert_count > 0).length;

  return (
    <Card
      title="ATT&CK coverage matrix"
      actions={
        <label className="check">
          <input type="checkbox" checked={onlyHits} onChange={(e) => setOnlyHits(e.target.checked)} />
          Only techniques seen in alerts
        </label>
      }
    >
      <p className="muted small">
        {covered} of {(data.techniques || []).length} catalogued techniques have been observed in alerts. Highlighted cells show the
        alert count.
      </p>
      <div className="matrix-wrap" tabIndex={0} role="region" aria-label="ATT&CK tactic matrix">
        <div className="matrix" style={{ gridTemplateColumns: `repeat(${tactics.length || 1}, minmax(150px, 1fr))` }}>
          {tactics.map((tac) => {
            const list = byTactic[tac].filter((t) => !onlyHits || t.alert_count > 0);
            const hits = byTactic[tac].reduce((s, t) => s + t.alert_count, 0);
            return (
              <div key={tac} className="matrix-col">
                <div className={`matrix-head ${hits ? "hot" : ""}`}>
                  <div>{tac}</div>
                  <div className="tiny">{byTactic[tac].length} techniques · {hits} hits</div>
                </div>
                {list.map((t) => (
                  <a
                    key={t.id}
                    href={t.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={`matrix-cell ${t.alert_count > 0 ? "hit" : ""}`}
                    title={t.description}
                  >
                    <span className="mono tiny">{t.id}</span>
                    <span>{t.name}</span>
                    {t.alert_count > 0 && <span className="cell-count">{t.alert_count} alert{t.alert_count === 1 ? "" : "s"}</span>}
                  </a>
                ))}
                {!list.length && <div className="matrix-empty tiny muted">none</div>}
              </div>
            );
          })}
        </div>
      </div>
    </Card>
  );
}

function Playbooks() {
  const { data, error, loading, reload } = useApi("/playbooks");
  if (loading && !data) return <Loading text="Loading playbooks…" />;
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  const list = data || [];
  if (!list.length) return <Empty>No playbooks configured.</Empty>;
  return (
    <div className="playbooks">
      {list.map((p) => (
        <details key={p.id} className="card playbook">
          <summary>
            <span className="pb-title">{p.name}</span>
            <span className="muted small mono">{p.id}</span>
          </summary>
          <div className="card-body">
            {p.description && <p>{p.description}</p>}
            {p.triggers && (
              <div className="pb-triggers small">
                {p.triggers.tactics?.length > 0 && (
                  <div>
                    <strong>Tactics:</strong> {p.triggers.tactics.join(", ")}
                  </div>
                )}
                {p.triggers.techniques?.length > 0 && (
                  <div>
                    <strong>Techniques:</strong> <span className="mono">{p.triggers.techniques.join(", ")}</span>
                  </div>
                )}
                {p.triggers.keywords?.length > 0 && (
                  <div>
                    <strong>Keywords:</strong> {p.triggers.keywords.join(", ")}
                  </div>
                )}
              </div>
            )}
            <ol className="pb-steps">
              {(p.steps || []).map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
          </div>
        </details>
      ))}
    </div>
  );
}

export default function Knowledge() {
  const { data, error, loading, reload } = useApi("/mitre");
  return (
    <div className="page">
      <PageHeader title="ATT&CK & Playbooks" subtitle="MITRE ATT&CK technique coverage and response playbooks" />
      {loading && !data ? <Loading text="Loading ATT&CK catalogue…" /> : error ? <ErrorBox error={error} onRetry={reload} /> : data && <Matrix data={data} />}
      <h2 className="section-title">Response playbooks</h2>
      <Playbooks />
    </div>
  );
}
