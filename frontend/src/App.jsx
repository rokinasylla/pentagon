import { useEffect, useState } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import * as api from "./api/client.js";
import Login from "./views/Login.jsx";
import Console from "./views/Console.jsx";
import Admin from "./views/Admin.jsx";
import Overview from "./views/Overview.jsx";
import Mission from "./views/Mission.jsx";

// Racine : vérifie l'état de session (api/v1/me) puis route vers la connexion
// ou la console. L'auth repose sur le cookie de session Flask.
export default function App() {
  const [auth, setAuth] = useState({ loading: true, user: null });

  const refresh = async () => {
    try {
      const data = await api.me();
      setAuth({
        loading: false,
        user: data.authenticated
          ? { operator: data.operator, role: data.role, sites: data.sites || [] }
          : null,
      });
    } catch {
      setAuth({ loading: false, user: null });
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  if (auth.loading) {
    return <div className="loading">Chargement…</div>;
  }

  return (
    <Routes>
      <Route
        path="/login"
        element={
          auth.user ? (
            <Navigate to="/" replace />
          ) : (
            <Login onAuthed={refresh} />
          )
        }
      />
      <Route
        path="/"
        element={
          auth.user ? (
            <Console user={auth.user} onLogout={refresh} />
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
      <Route
        path="/mission"
        element={
          auth.user ? (
            <Mission user={auth.user} onLogout={refresh} />
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
      <Route
        path="/overview"
        element={
          auth.user ? (
            <Overview user={auth.user} onLogout={refresh} />
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
      <Route
        path="/admin"
        element={
          !auth.user ? (
            <Navigate to="/login" replace />
          ) : auth.user.role === "admin" ? (
            <Admin user={auth.user} onLogout={refresh} />
          ) : (
            <Navigate to="/" replace />
          )
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
