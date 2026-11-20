import { useState } from "react";
import { api } from "../api.js";
import {
  Button,
  Card,
  Empty,
  ErrorBox,
  Loading,
  Notice,
  PageHeader,
  Select,
  TableWrap,
  formatDate,
  useApi,
} from "../components/ui.jsx";

const ROLES = ["analyst", "viewer", "admin"];
const EMPTY = { username: "", full_name: "", role: "analyst", password: "" };

function detailsText(d) {
  if (d == null || d === "") return "";
  if (typeof d === "string") return d;
  try {
    return JSON.stringify(d);
  } catch {
    return String(d);
  }
}

export default function Admin() {
  const users = useApi("/auth/users");
  const audit = useApi("/auth/audit?limit=200");
  const [form, setForm] = useState(EMPTY);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState("");

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setCreated("");
    if (!/^[A-Za-z0-9._-]{3,64}$/.test(form.username.trim())) {
      setError("Username must be 3–64 characters: letters, digits, dot, underscore or hyphen.");
      return;
    }
    if (form.password.length < 10) {
      setError("Password must be at least 10 characters.");
      return;
    }
    setBusy(true);
    try {
      const u = await api("/auth/users", {
        method: "POST",
        body: { username: form.username.trim(), full_name: form.full_name.trim(), role: form.role, password: form.password },
      });
      setCreated(`Created ${u.role} account "${u.username}".`);
      setForm(EMPTY);
      users.reload();
      audit.reload();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <PageHeader title="Administration" subtitle="Users, roles and the audit trail" />
      <div className="grid-2 wide-left">
        <Card title="Users">
          <ErrorBox error={users.error} onRetry={users.reload} />
          {users.loading && !users.data ? (
            <Loading />
          ) : (users.data || []).length === 0 ? (
            <Empty>No users.</Empty>
          ) : (
            <TableWrap label="Users">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Username</th>
                    <th scope="col">Full name</th>
                    <th scope="col">Role</th>
                    <th scope="col">Active</th>
                    <th scope="col">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {users.data.map((u) => (
                    <tr key={u.id}>
                      <td className="mono">{u.username}</td>
                      <td>{u.full_name || "—"}</td>
                      <td>
                        <span className={`chip role-${u.role}`}>{u.role}</span>
                      </td>
                      <td>{u.is_active ? "yes" : "no"}</td>
                      <td className="nowrap">{formatDate(u.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </Card>
        <Card title="Create user">
          <form className="stack" onSubmit={submit} noValidate>
            <div className="field">
              <label htmlFor="nu-username">Username</label>
              <input id="nu-username" autoComplete="off" value={form.username} onChange={set("username")} maxLength={64} />
            </div>
            <div className="field">
              <label htmlFor="nu-fullname">Full name</label>
              <input id="nu-fullname" autoComplete="off" value={form.full_name} onChange={set("full_name")} maxLength={128} />
            </div>
            <Select label="Role" value={form.role} onChange={(v) => setForm((f) => ({ ...f, role: v }))} options={ROLES} id="nu-role" />
            <div className="field">
              <label htmlFor="nu-password">Password (min 10 characters)</label>
              <input id="nu-password" type="password" autoComplete="new-password" value={form.password} onChange={set("password")} maxLength={128} />
            </div>
            <ErrorBox error={error} />
            {created && <Notice tone="ok">{created}</Notice>}
            <div>
              <Button type="submit" className="btn-primary" busy={busy}>
                Create user
              </Button>
            </div>
          </form>
        </Card>
      </div>
      <Card title="Audit log (latest 200)" actions={<button type="button" className="btn btn-sm" onClick={audit.reload}>Refresh</button>}>
        <ErrorBox error={audit.error} onRetry={audit.reload} />
        {audit.loading && !audit.data ? (
          <Loading />
        ) : (audit.data || []).length === 0 ? (
          <Empty>No audit entries.</Empty>
        ) : (
          <TableWrap label="Audit log">
            <table>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Actor</th>
                  <th scope="col">Action</th>
                  <th scope="col">Entity</th>
                  <th scope="col">Details</th>
                </tr>
              </thead>
              <tbody>
                {audit.data.map((x) => (
                  <tr key={x.id}>
                    <td className="nowrap">{formatDate(x.created_at, true)}</td>
                    <td className="mono">{x.actor}</td>
                    <td>{x.action}</td>
                    <td className="nowrap">
                      {x.entity}
                      {x.entity_id ? ` #${x.entity_id}` : ""}
                    </td>
                    <td className="mono small break audit-details">{detailsText(x.details)}</td>
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
