import { useCallback, useEffect, useMemo, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api, clearToken, getToken } from "./api.js";
import Layout from "./components/Layout.jsx";
import { AuthContext, ErrorBox, Loading } from "./components/ui.jsx";
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Alerts from "./pages/Alerts.jsx";
import AlertDetail from "./pages/AlertDetail.jsx";
import Cases from "./pages/Cases.jsx";
import CaseDetail from "./pages/CaseDetail.jsx";
import Vulnerabilities from "./pages/Vulnerabilities.jsx";
import Knowledge from "./pages/Knowledge.jsx";
import Admin from "./pages/Admin.jsx";

function RequireAuth({ user, children }) {
  const location = useLocation();
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return children;
}

function NotFound() {
  return (
    <div className="page">
      <h1>Page not found</h1>
      <p className="muted">That page does not exist.</p>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(!!getToken());
  const [bootError, setBootError] = useState("");

  const loadMe = useCallback(async () => {
    if (!getToken()) {
      setChecking(false);
      return;
    }
    setChecking(true);
    setBootError("");
    try {
      setUser(await api("/auth/me"));
    } catch (e) {
      if (e.status === 401 || e.status === 403) clearToken();
      else setBootError(e.message);
      setUser(null);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    loadMe();
  }, [loadMe]);

  const logout = useCallback(() => {
    clearToken();
    setUser(null);
  }, []);

  const ctx = useMemo(() => ({ user, setUser, logout }), [user, logout]);

  if (checking) return <Loading text="Checking session…" />;
  if (bootError)
    return (
      <div className="page boot-error">
        <ErrorBox error={bootError} onRetry={loadMe} />
      </div>
    );

  return (
    <AuthContext.Provider value={ctx}>
      <Routes>
        <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />
        <Route
          element={
            <RequireAuth user={user}>
              <Layout />
            </RequireAuth>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="alerts/:id" element={<AlertDetail />} />
          <Route path="cases" element={<Cases />} />
          <Route path="cases/:id" element={<CaseDetail />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="knowledge" element={<Knowledge />} />
          <Route path="admin" element={user && user.role === "admin" ? <Admin /> : <Navigate to="/" replace />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </AuthContext.Provider>
  );
}
