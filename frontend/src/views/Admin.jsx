import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import * as api from "../api/client.js";
import Brand from "../components/Brand.jsx";

// Écran d'administration (Lot UI-5) : comptes et SITES AUTORISÉS par opérateur.
// L'admin attribue à chaque opérateur un sous-ensemble de la liste blanche
// globale ; un opérateur simple ne peut cibler que ses sites.
export default function Admin({ user, onLogout }) {
  const navigate = useNavigate();
  const [users, setUsers] = useState([]);
  const [whitelist, setWhitelist] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [savingFor, setSavingFor] = useState("");

  const load = () => {
    setLoading(true);
    api
      .adminListUsers()
      .then((d) => {
        setUsers(d.users || []);
        setWhitelist(d.whitelist || []);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const toggleSite = async (u, site) => {
    const has = u.sites.includes(site);
    const next = has ? u.sites.filter((s) => s !== site) : [...u.sites, site];
    setSavingFor(u.username);
    setError("");
    try {
      const r = await api.adminSetUserSites(u.username, next);
      setUsers((list) =>
        list.map((x) => (x.username === u.username ? { ...x, sites: r.sites } : x))
      );
    } catch (e) {
      setError(e.message);
    } finally {
      setSavingFor("");
    }
  };

  const doLogout = async () => {
    try {
      await api.logout();
    } finally {
      await onLogout();
    }
  };

  return (
    <div className="shell">
      <header className="topbar">
        <Brand />
        <div className="who">
          <button onClick={() => navigate("/")}>← Console</button>
          <span>
            {user.operator} ({user.role})
          </span>
          <button onClick={doLogout}>Déconnexion</button>
        </div>
      </header>

      <div className="admin-wrap">
        <h1 className="admin-h1">Administration</h1>
        <p className="fc-meta">
          Comptes et sites autorisés par opérateur. Un opérateur simple ne peut
          lancer de campagne que sur les sites qui lui sont attribués.
        </p>

        {error && <div className="err">{error}</div>}
        {loading && <div className="loading">Chargement…</div>}

        {!loading && whitelist.length === 0 && (
          <div className="empty">
            Aucune cible dans la liste blanche globale (roe_policy.json). Ajoutez
            des cibles autorisées avant de les attribuer.
          </div>
        )}

        {!loading &&
          users.map((u) => (
            <div key={u.username} className="admin-card">
              <div className="admin-card-head">
                <div>
                  <strong>{u.username}</strong>
                  <span className={`role-badge ${u.role}`}>{u.role}</span>
                </div>
                {savingFor === u.username && (
                  <span className="fc-meta">enregistrement…</span>
                )}
              </div>

              {u.role === "admin" ? (
                <div className="fc-meta">
                  Accès non restreint (administrateur) — borné à la liste blanche globale.
                </div>
              ) : whitelist.length === 0 ? null : (
                <div className="site-checks">
                  {whitelist.map((site) => (
                    <label key={site} className="site-check">
                      <input
                        type="checkbox"
                        checked={u.sites.includes(site)}
                        disabled={savingFor === u.username}
                        onChange={() => toggleSite(u, site)}
                      />
                      <span>{site}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          ))}
      </div>
    </div>
  );
}
