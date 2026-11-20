// Thin fetch wrapper for the SentinelAI FastAPI backend (same origin, base /api).
const TOKEN_KEY = "sentinel_token";
const BASE = "/api";

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY) || "";
  } catch {
    return "";
  }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable (private mode); session lasts for this page only */
  }
}

export function clearToken() {
  setToken("");
}

// Formats a FastAPI `detail` (string, 422 validation list, or object) into readable text.
export function formatDetail(detail, fallback = "Request failed") {
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        if (typeof d === "string") return d;
        const loc = Array.isArray(d.loc) ? d.loc.filter((p) => p !== "body").join(".") : "";
        return loc ? `${loc}: ${d.msg}` : d.msg || JSON.stringify(d);
      })
      .join("; ");
  }
  if (typeof detail === "object") return detail.msg || JSON.stringify(detail);
  return String(detail);
}

function handleUnauthorized() {
  clearToken();
  if (window.location.pathname !== "/login") {
    window.location.assign("/login");
  }
}

async function errorFrom(res) {
  let detail = null;
  try {
    const data = await res.json();
    detail = data && data.detail;
  } catch {
    /* non-JSON error body */
  }
  const err = new Error(formatDetail(detail, `${res.status} ${res.statusText || "Request failed"}`));
  err.status = res.status;
  return err;
}

// api(path, { method, body, form }) -> parsed JSON (or text / null)
export async function api(path, { method, body, form, raw } = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload;
  if (form) {
    payload = form; // FormData: let the browser set the multipart boundary
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(BASE + path, { method: method || (payload ? "POST" : "GET"), headers, body: payload });
  } catch {
    throw new Error("Cannot reach the SentinelAI API. Is the backend running?");
  }
  if (res.status === 401 && path !== "/auth/login") {
    handleUnauthorized();
    throw new Error("Session expired. Please sign in again.");
  }
  if (!res.ok) throw await errorFrom(res);
  if (raw) return res;
  if (res.status === 204) return null;
  const type = res.headers.get("content-type") || "";
  return type.includes("application/json") ? res.json() : res.text();
}

export async function login(username, password) {
  const form = new URLSearchParams({ username, password });
  let res;
  try {
    res = await fetch(`${BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
  } catch {
    throw new Error("Cannot reach the SentinelAI API. Is the backend running?");
  }
  if (!res.ok) throw await errorFrom(res);
  const data = await res.json();
  setToken(data.access_token);
  return data.user;
}

export async function downloadCaseReport(caseId) {
  const res = await api(`/cases/${caseId}/report`, { raw: true });
  const blob = await res.blob();
  let filename = `case-${caseId}-incident-report.md`;
  const cd = res.headers.get("content-disposition") || "";
  const m = cd.match(/filename="?([^";]+)"?/i);
  if (m) filename = m[1];
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function qs(params) {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") p.set(k, v);
  });
  const s = p.toString();
  return s ? `?${s}` : "";
}
