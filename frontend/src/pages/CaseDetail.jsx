import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, downloadCaseReport } from "../api.js";
import {
  ACTION_TYPES,
  AiReport,
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
  VerdictChip,
  formatDate,
  label,
  useApi,
  useCanWrite,
} from "../components/ui.jsx";

const SUGGESTIONS = [
  "Summarise this incident",
  "Which IOCs should we block?",
  "Show the timeline",
  "Which ATT&CK techniques were used?",
  "Are the affected assets vulnerable?",
  "What should I do next?",
];

function ChatPanel({ c, canWrite, onChat }) {
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const listRef = useRef(null);
  const chat = c.chat || [];

  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [chat.length, busy]);

  const send = async (text) => {
    const msg = (text ?? message).trim();
    if (!msg || busy) return;
    setBusy(true);
    setError("");
    setNote("");
    try {
      const res = await api(`/cases/${c.id}/chat`, { method: "POST", body: { message: msg.slice(0, 2000) } });
      onChat(res.chat);
      setNote(res.engine_note || "");
      setMessage("");
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="chat">
      <div className="chat-log" ref={listRef} aria-live="polite" aria-label="Case chat messages" role="log" tabIndex={0}>
        {chat.length === 0 && !busy && <Empty>Ask SentinelAI about this case. Answers are grounded in the case data only.</Empty>}
        {chat.map((m) => (
          <div key={m.id} className={`msg msg-${m.role}`}>
            <div className="msg-meta">
              <strong>{m.role === "assistant" ? m.author || "SentinelAI" : m.author || "you"}</strong>
              {m.engine && <span className="chip engine-chip">{m.engine}</span>}
              <span className="muted small">{formatDate(m.created_at)}</span>
            </div>
            <div className="prewrap">{m.content}</div>
          </div>
        ))}
        {busy && (
          <div className="msg msg-assistant">
            <Loading text="SentinelAI is thinking…" />
          </div>
        )}
      </div>
      {note && <Notice tone="warn">{note}</Notice>}
      <ErrorBox error={error} />
      {canWrite ? (
        <>
          <div className="tag-list suggestions" aria-label="Suggested questions">
            {SUGGESTIONS.map((s) => (
              <button key={s} type="button" className="chip-btn" onClick={() => send(s)} disabled={busy}>
                {s}
              </button>
            ))}
          </div>
          <form
            className="chat-input"
            onSubmit={(e) => {
              e.preventDefault();
              send();
            }}
          >
            <label htmlFor="chat-msg" className="sr-only">
              Ask about this case
            </label>
            <input
              id="chat-msg"
              value={message}
              maxLength={2000}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Ask about this incident…"
              disabled={busy}
            />
            <button type="submit" className="btn btn-primary" disabled={busy || !message.trim()}>
              Send
            </button>
          </form>
        </>
      ) : (
        <p className="muted small">Viewers have read-only access to the chat history.</p>
      )}
    </div>
  );
}

export default function CaseDetail() {
  const { id } = useParams();
  const canWrite = useCanWrite();
  const { data: c, error, loading, reload, setData } = useApi(`/cases/${id}`);
  const [busy, setBusy] = useState("");
  const [actionError, setActionError] = useState("");
  const [assignee, setAssignee] = useState("");
  const [noteText, setNoteText] = useState("");
  const [manual, setManual] = useState({ action: "isolate_host", target: "", details: "" });

  useEffect(() => {
    if (c) setAssignee(c.assignee || "");
  }, [c?.id, c?.assignee]); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading && !c) return <Loading text="Loading case…" />;
  if (error && !c) return <ErrorBox error={error} onRetry={reload} />;
  if (!c) return null;

  const run = async (key, fn) => {
    setBusy(key);
    setActionError("");
    try {
      const res = await fn();
      if (res) setData(res);
      return true;
    } catch (e) {
      setActionError(e.message);
      return false;
    } finally {
      setBusy("");
    }
  };

  const patch = (body, key) => run(key, () => api(`/cases/${c.id}`, { method: "PATCH", body }));
  const investigate = () => run("investigate", () => api(`/cases/${c.id}/investigate`, { method: "POST" }));
  const runAction = (action, target, details = "", key) =>
    run(key || `act-${action}-${target}`, () =>
      api(`/cases/${c.id}/actions`, { method: "POST", body: { action, target, details } })
    );
  const download = () => run("report", async () => {
    await downloadCaseReport(c.id);
    return null;
  });

  const addNote = async (e) => {
    e.preventDefault();
    if (!noteText.trim()) return;
    if (await run("note", () => api(`/cases/${c.id}/notes`, { method: "POST", body: { content: noteText.trim() } })))
      setNoteText("");
  };

  const submitManual = async (e) => {
    e.preventDefault();
    if (!manual.target.trim()) {
      setActionError("Enter a target for the action.");
      return;
    }
    if (await runAction(manual.action, manual.target.trim(), manual.details.trim(), "manual"))
      setManual((m) => ({ ...m, target: "", details: "" }));
  };

  const done = (action, target) => (c.actions || []).some((x) => x.action === action && x.target === target);
  const recommended = c.ai_report?.recommended_actions || [];

  const actionsSlot = recommended.length ? (
    <>
      <h3>Recommended actions</h3>
      <ul className="action-list">
        {recommended.map((a, i) => {
          const isDone = done(a.action, a.target);
          const key = `act-${a.action}-${a.target}`;
          return (
            <li key={i} className="action-row">
              <div>
                <span className={`chip prio-${a.priority || "normal"}`}>{a.priority || "normal"}</span>{" "}
                <strong>{label(a.action)}</strong> <code>{a.target}</code>
                {a.reason && <div className="muted small">{a.reason}</div>}
              </div>
              {isDone ? (
                <span className="done-tick" aria-label="Action already executed">
                  ✓ done
                </span>
              ) : canWrite ? (
                <Button className="btn-sm" busy={busy === key} disabled={!!busy} onClick={() => runAction(a.action, a.target, a.reason ? `AI recommendation: ${a.reason}`.slice(0, 2000) : "", key)}>
                  Run
                </Button>
              ) : null}
            </li>
          );
        })}
      </ul>
    </>
  ) : null;

  return (
    <div className="page">
      <p className="crumbs">
        <Link to="/cases">← Cases</Link>
      </p>
      <PageHeader title={c.title} subtitle={`Case #${c.id} · created by ${c.created_by} · ${formatDate(c.created_at)}`}>
        <Button busy={busy === "report"} onClick={download}>
          Download report
        </Button>
        {canWrite && (
          <Button className="btn-primary" busy={busy === "investigate"} disabled={!!busy || !c.alerts?.length} onClick={investigate}>
            {busy === "investigate" ? "Analysing…" : "Run AI incident analysis"}
          </Button>
        )}
      </PageHeader>

      <Card>
        <div className="detail-head">
          <div className="detail-badges">
            <span className="meta-item">
              Severity <SeverityPill severity={c.severity} />
            </span>
            <span className="meta-item">
              Max risk <RiskBadge score={c.max_risk} />
            </span>
            <span className="meta-item">Alerts {c.alert_count}</span>
            {c.verdict && (
              <span className="meta-item">
                AI verdict <VerdictChip verdict={c.verdict} />
              </span>
            )}
            {!canWrite && (
              <>
                <span className="meta-item">
                  Status <StatusChip status={c.status} />
                </span>
                <span className="meta-item">Assignee {c.assignee || "—"}</span>
              </>
            )}
          </div>
          {canWrite && (
            <div className="row wrap">
              <Select label="Status" value={c.status} onChange={(v) => patch({ status: v }, "status")} options={CASE_STATUSES} disabled={!!busy} id="case-status" />
              <form
                className="row inline-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  patch({ assignee: assignee.trim() }, "assignee");
                }}
              >
                <div className="field">
                  <label htmlFor="case-assignee">Assignee</label>
                  <input id="case-assignee" value={assignee} maxLength={64} onChange={(e) => setAssignee(e.target.value)} />
                </div>
                <button type="submit" className="btn btn-sm" disabled={!!busy || assignee.trim() === (c.assignee || "")}>
                  Save
                </button>
              </form>
            </div>
          )}
        </div>
        <ErrorBox error={actionError} />
        {c.summary && <p className="prewrap">{c.summary}</p>}
        <div className="muted small">
          Updated {formatDate(c.updated_at)}
          {c.closed_at && ` · closed ${formatDate(c.closed_at)}`}
        </div>
      </Card>

      <div className="grid-2 wide-left">
        <Card title="AI incident analysis" className="ai-card">
          {busy === "investigate" ? (
            <Loading text="AI is analysing the incident…" />
          ) : (
            <AiReport report={c.ai_report} actionsSlot={actionsSlot} />
          )}
          {!c.ai_report && canWrite && c.alerts?.length > 0 && (
            <p className="muted small">Run the AI incident analysis to get a verdict, narrative and recommended actions.</p>
          )}
        </Card>
        <Card title="Ask SentinelAI">
          <ChatPanel c={c} canWrite={canWrite} onChat={(chat) => setData({ ...c, chat })} />
        </Card>
      </div>

      <Card title="Alert timeline">
        {c.alerts?.length ? (
          <ol className="timeline">
            {c.alerts.map((a) => (
              <li key={a.id} className={`tl-item tl-${a.severity}`}>
                <div className="tl-time">{formatDate(a.event_time, true)}</div>
                <div className="tl-body">
                  <div>
                    <SeverityPill severity={a.severity} /> <RiskBadge score={a.risk_score} />{" "}
                    <Link to={`/alerts/${a.id}`}>{a.title}</Link>
                  </div>
                  <div className="muted small">
                    #{a.id} · {a.source} · {a.host || "no host"}
                    {a.username ? ` · ${a.username}` : ""}
                    {a.tactics?.length ? ` · ${a.tactics.join(", ")}` : ""}
                  </div>
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <Empty>No alerts in this case.</Empty>
        )}
      </Card>

      <div className="grid-2">
        <Card title="Response actions">
          <Notice tone="info">Response actions are simulated — nothing touches a real system. Every action is audited.</Notice>
          {canWrite && (
            <form className="stack" onSubmit={submitManual}>
              <div className="row wrap">
                <Select
                  label="Action"
                  value={manual.action}
                  onChange={(v) => setManual((m) => ({ ...m, action: v }))}
                  options={ACTION_TYPES}
                  id="manual-action"
                />
                <div className="field grow">
                  <label htmlFor="manual-target">Target</label>
                  <input
                    id="manual-target"
                    value={manual.target}
                    maxLength={512}
                    placeholder="host, IP, domain, user, hash…"
                    onChange={(e) => setManual((m) => ({ ...m, target: e.target.value }))}
                  />
                </div>
              </div>
              <div className="field">
                <label htmlFor="manual-details">Details (optional)</label>
                <input
                  id="manual-details"
                  value={manual.details}
                  maxLength={2000}
                  onChange={(e) => setManual((m) => ({ ...m, details: e.target.value }))}
                />
              </div>
              <div>
                <Button type="submit" className="btn-primary" busy={busy === "manual"} disabled={!!busy}>
                  Execute action
                </Button>
              </div>
            </form>
          )}
          <h3 className="sub-head">Action log</h3>
          {c.actions?.length ? (
            <ul className="log-list">
              {[...c.actions].reverse().map((x) => (
                <li key={x.id}>
                  <div>
                    <strong>{label(x.action)}</strong> <code>{x.target}</code> <span className="chip status-simulated">{x.status}</span>
                  </div>
                  <div className="small">{x.details}</div>
                  <div className="muted small">
                    by {x.performed_by} · {formatDate(x.created_at)}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>No actions taken yet.</Empty>
          )}
        </Card>

        <Card title="Analyst notes">
          {canWrite && (
            <form className="stack" onSubmit={addNote}>
              <div className="field">
                <label htmlFor="note-text">Add a note</label>
                <textarea id="note-text" rows={3} maxLength={8000} value={noteText} onChange={(e) => setNoteText(e.target.value)} />
              </div>
              <div>
                <Button type="submit" busy={busy === "note"} disabled={!!busy || !noteText.trim()}>
                  Add note
                </Button>
              </div>
            </form>
          )}
          {c.notes?.length ? (
            <ul className="log-list">
              {[...c.notes].reverse().map((n) => (
                <li key={n.id}>
                  <div className="prewrap">{n.content}</div>
                  <div className="muted small">
                    {n.author} · {formatDate(n.created_at)}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>No notes yet.</Empty>
          )}
        </Card>
      </div>
    </div>
  );
}
