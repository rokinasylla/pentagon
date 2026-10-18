import { useEffect, useState } from "react";
import * as api from "../api/client.js";
import TopNav from "../components/TopNav.jsx";

const SECTIONS = [
  { id: "account", label: "Mon compte" },
  { id: "users", label: "Utilisateurs" },
  { id: "sites", label: "Sites autorisés" },
];

export default function Admin({ user, onLogout }) {
  const [sec, setSec] = useState("users");
  const [users, setUsers] = useState([]);
  const [sites, setSites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [nu, setNu] = useState({ username: "", password: "", role: "user" });
  const [newSite, setNewSite] = useState("");

  const load = () => {
    setLoading(true);
    Promise.all([api.adminListUsers(), api.adminListSites()])
      .then(([u, s]) => { setUsers(u.users || []); setSites(s.sites || []); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };
  useEffect(load, []);

  const act = async (fn, okMsg) => {
    setError(""); setNotice("");
    try { await fn(); if (okMsg) setNotice(okMsg); load(); }
    catch (e) { setError(e.message); }
  };

  const createUser = async (e) => {
    e.preventDefault();
    const u = nu.username.trim();
    await act(() => api.adminCreateUser(u, nu.password, nu.role), `Compte « ${u} » créé.`);
    setNu({ username: "", password: "", role: "user" });
  };

  const addSite = async (e) => {
    e.preventDefault();
    const s = newSite.trim();
    await act(() => api.adminAddSite(s), `Site « ${s} » autorisé.`);
    setNewSite("");
  };

  const initials = (n) => (n || "?").slice(0, 2).toUpperCase();

  return (
    <div className="page">
      <TopNav active="reglages" user={user} onLogout={onLogout} />

      <main className="page-main">
        <div className="settings">
          <aside className="set-nav">
            <div className="set-eyebrow">Réglages</div>
            {SECTIONS.map((s) => (
              <button key={s.id} className={`set-link ${sec === s.id ? "on" : ""}`} onClick={() => setSec(s.id)}>
                {s.label}
              </button>
            ))}
          </aside>

          <div className="set-content">
            {error && <div className="err">{error}</div>}
            {notice && <div className="msg good"><div className="body">{notice}</div></div>}

            {/* ─── Mon compte ─── */}
            {sec === "account" && (
              <section className="fcard">
                <h2 className="set-h2">Mon compte</h2>
                <div className="acct">
                  <span className="acct-avatar">{initials(user.operator)}</span>
                  <div>
                    <div className="acct-name">{user.operator}</div>
                    <div className="fc-meta">Administrateur</div>
                  </div>
                </div>
                <p className="fc-meta" style={{ marginTop: 14 }}>
                  Modèle d'accès : l'administrateur gère les comptes et la liste des
                  sites autorisés, indépendamment l'un de l'autre. Un opérateur peut
                  lancer une campagne sur tout site autorisé ; sinon, c'est bloqué.
                </p>
              </section>
            )}

            {/* ─── Utilisateurs (comptes seulement) ─── */}
            {sec === "users" && (
              <>
                <section className="fcard">
                  <div className="set-h-row">
                    <h2 className="set-h2">Utilisateurs</h2>
                    <span className="fc-meta">{users.length} compte{users.length > 1 ? "s" : ""}</span>
                  </div>
                  {loading && <div className="loading">Chargement…</div>}
                  <div className="utable">
                    <div className="ut-head"><span>Utilisateur</span><span>Rôle</span><span></span></div>
                    {users.map((u) => (
                      <div key={u.username} className="ut-row simple3">
                        <span className="ut-user">
                          <span className="ut-avatar">{initials(u.username)}</span>
                          <span>{u.username}{u.username === user.operator && <span className="fc-meta"> · vous</span>}</span>
                        </span>
                        <span><span className={`role-badge ${u.role}`}>{u.role}</span></span>
                        <span className="ut-ops">
                          <button className="ghost sm" onClick={() => act(() => api.adminSetUserRole(u.username, u.role === "admin" ? "user" : "admin"), "Rôle mis à jour.")}>
                            {u.role === "admin" ? "Rétrograder" : "Promouvoir"}
                          </button>
                          <button className="ghost sm danger" disabled={u.username === user.operator}
                            onClick={() => { if (confirm(`Supprimer « ${u.username} » ?`)) act(() => api.adminDeleteUser(u.username), "Compte supprimé."); }}>
                            Supprimer
                          </button>
                        </span>
                      </div>
                    ))}
                  </div>
                </section>

                <form className="fcard" onSubmit={createUser}>
                  <h2 className="set-h2">Nouvel utilisateur</h2>
                  <p className="fc-meta" style={{ marginBottom: 14 }}>
                    Le compte pourra lancer des campagnes sur les sites autorisés.
                  </p>
                  <div className="new-user">
                    <input placeholder="Identifiant" value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} autoComplete="off" />
                    <input type="password" placeholder="Mot de passe (min. 6)" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.target.value })} autoComplete="new-password" />
                    <select value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })}>
                      <option value="user">Opérateur</option>
                      <option value="admin">Admin</option>
                    </select>
                    <button className="primary" type="submit" disabled={!nu.username.trim() || nu.password.length < 6}>Créer</button>
                  </div>
                </form>
              </>
            )}

            {/* ─── Sites autorisés (liste globale) ─── */}
            {sec === "sites" && (
              <>
                <section className="fcard">
                  <div className="set-h-row">
                    <h2 className="set-h2">Sites autorisés</h2>
                    <span className="fc-meta">{sites.length} autorisé{sites.length > 1 ? "s" : ""}</span>
                  </div>
                  <p className="fc-meta" style={{ marginBottom: 14 }}>
                    Liste blanche globale. Tout opérateur peut lancer une campagne sur
                    un site qui y figure ; tout autre site est bloqué.
                  </p>
                  {loading && <div className="loading">Chargement…</div>}
                  <div className="utable">
                    {sites.length === 0 && <div className="fc-meta" style={{ padding: 12 }}>Aucun site autorisé pour l'instant.</div>}
                    {sites.map((s) => (
                      <div key={s} className="ut-row simple">
                        <span className="mono">{s}</span>
                        <span className="ut-ops">
                          <button className="ghost sm danger"
                            onClick={() => { if (confirm(`Retirer « ${s} » des sites autorisés ?`)) act(() => api.adminRemoveSite(s), "Site retiré."); }}>
                            Retirer
                          </button>
                        </span>
                      </div>
                    ))}
                  </div>
                </section>

                <form className="fcard" onSubmit={addSite}>
                  <h2 className="set-h2">Autoriser un site</h2>
                  <p className="fc-meta" style={{ marginBottom: 14 }}>
                    En autorisant, vous attestez disposer du droit légal de faire tester cette cible.
                  </p>
                  <div className="add-site">
                    <input placeholder="domaine ou URL (ex. exemple.com)" value={newSite}
                      onChange={(e) => setNewSite(e.target.value)} autoComplete="off" />
                    <button className="primary" type="submit" disabled={!newSite.trim()}>Autoriser le site</button>
                  </div>
                </form>
              </>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
