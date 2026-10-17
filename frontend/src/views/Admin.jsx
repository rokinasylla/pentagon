import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import * as api from "../api/client.js";
import Brand from "../components/Brand.jsx";

// Écran d'administration (Lot UI-5) : GESTION DES COMPTES (créer / changer de
// rôle / supprimer) ET sites autorisés par opérateur (ACL). Admin only.
export default function Admin({ user, onLogout }) {
  const navigate = useNavigate();
  const [users, setUsers] = useState([]);
  const [whitelist, setWhitelist] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [savingFor, setSavingFor] = useState("");

  // Formulaire de création / réinitialisation
  const [nu, setNu] = useState({ username: "", password: "", role: "user" });
  const [creating, setCreating] = useState(false);
  const [notice, setNotice] = useState("");

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

  const act = async (fn, okMsg) => {
    setError("");
    setNotice("");
    try {
      await fn();
      if (okMsg) setNotice(okMsg);
      load();
    } catch (e) {
      setError(e.message);
    }
  };

  const createUser = async (e) => {
    e.preventDefault();
    setCreating(true);
    await act(
      () => api.adminCreateUser(nu.username.trim(), nu.password, nu.role),
      `Compte « ${nu.username.trim()} » enregistré.`
    );
    setNu({ username: "", password: "", role: "user" });
    setCreating(false);
  };

  const toggleSite = async (u, site) => {
    const next = u.sites.includes(site)
      ? u.sites.filter((s) => s !== site)
      : [...u.sites, site];
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
    try { await api.logout(); } finally { await onLogout(); }
  };

  return (
    <div className="shell">
      <header className="topbar">
        <Brand />
        <div className="who">
          <button onClick={() => navigate("/")}>← Console</button>
          <span>{user.operator} ({user.role})</span>
          <button onClick={doLogout}>Déconnexion</button>
        </div>
      </header>

      <div className="admin-wrap">
        <h1 className="admin-h1">Administration</h1>
        <p className="fc-meta">
          Gérez les comptes et les sites autorisés par opérateur. Un opérateur
          simple ne peut tester que les sites qui lui sont attribués.
        </p>

        {error && <div className="err">{error}</div>}
        {notice && <div className="msg good" style={{ marginBottom: 12 }}><div className="body">{notice}</div></div>}

        {/* Création / réinitialisation de compte */}
        <form className="admin-card" onSubmit={createUser}>
          <div className="audit-title" style={{ marginBottom: 10 }}>
            Créer ou réinitialiser un compte
          </div>
          <div className="new-user">
            <input
              placeholder="Identifiant"
              value={nu.username}
              onChange={(e) => setNu({ ...nu, username: e.target.value })}
              autoComplete="off"
            />
            <input
              type="password"
              placeholder="Mot de passe (min. 6)"
              value={nu.password}
              onChange={(e) => setNu({ ...nu, password: e.target.value })}
              autoComplete="new-password"
            />
            <select value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })}>
              <option value="user">Opérateur</option>
              <option value="admin">Administrateur</option>
            </select>
            <button className="primary" type="submit" disabled={creating || !nu.username.trim() || nu.password.length < 6}>
              {creating ? "…" : "Enregistrer"}
            </button>
          </div>
          <div className="fc-meta" style={{ marginTop: 8 }}>
            Un identifiant existant voit son mot de passe réinitialisé (l'ACL de sites est conservée).
          </div>
        </form>

        {loading && <div className="loading">Chargement…</div>}

        {/* Comptes existants : rôle, suppression, ACL de sites */}
        {!loading &&
          users.map((u) => (
            <div key={u.username} className="admin-card">
              <div className="admin-card-head">
                <div>
                  <strong>{u.username}</strong>
                  <span className={`role-badge ${u.role}`}>{u.role}</span>
                  {u.username === user.operator && <span className="fc-meta"> · vous</span>}
                </div>
                <div className="user-ops">
                  {savingFor === u.username && <span className="fc-meta">…</span>}
                  <button
                    className="ghost sm"
                    onClick={() =>
                      act(
                        () => api.adminSetUserRole(u.username, u.role === "admin" ? "user" : "admin"),
                        `Rôle de « ${u.username} » mis à jour.`
                      )
                    }
                  >
                    {u.role === "admin" ? "Rétrograder" : "Promouvoir admin"}
                  </button>
                  <button
                    className="ghost sm danger"
                    disabled={u.username === user.operator}
                    onClick={() => {
                      if (confirm(`Supprimer le compte « ${u.username} » ?`))
                        act(() => api.adminDeleteUser(u.username), `Compte « ${u.username} » supprimé.`);
                    }}
                  >
                    Supprimer
                  </button>
                </div>
              </div>

              {u.role === "admin" ? (
                <div className="fc-meta">
                  Accès non restreint (administrateur) — borné à la liste blanche globale.
                </div>
              ) : whitelist.length === 0 ? (
                <div className="fc-meta">
                  Aucune cible dans la liste blanche globale (roe_policy.json) à attribuer.
                </div>
              ) : (
                <>
                  <div className="fc-meta" style={{ margin: "4px 0 8px" }}>Sites autorisés :</div>
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
                </>
              )}
            </div>
          ))}
      </div>
    </div>
  );
}
