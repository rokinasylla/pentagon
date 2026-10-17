import { useEffect, useState } from "react";
import * as api from "../api/client.js";
import TopNav from "../components/TopNav.jsx";

const SECTIONS = [
  { id: "account", label: "Mon compte" },
  { id: "users", label: "Utilisateurs" },
  { id: "sites", label: "Sites autorisés" },
  { id: "roles", label: "Rôles & accès" },
  { id: "prefs", label: "Préférences" },
];

export default function Admin({ user, onLogout }) {
  const [sec, setSec] = useState("users");
  const [users, setUsers] = useState([]);
  const [whitelist, setWhitelist] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [savingFor, setSavingFor] = useState("");
  const [nu, setNu] = useState({ username: "", password: "", role: "user", sites: [] });

  const load = () => {
    setLoading(true);
    api.adminListUsers()
      .then((d) => { setUsers(d.users || []); setWhitelist(d.whitelist || []); })
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
    await act(async () => {
      await api.adminCreateUser(u, nu.password, nu.role);
      if (nu.role !== "admin" && nu.sites.length)
        await api.adminSetUserSites(u, nu.sites);
    }, `Compte « ${u} » créé.`);
    setNu({ username: "", password: "", role: "user", sites: [] });
  };

  const toggleSite = async (usr, site) => {
    const next = usr.sites.includes(site) ? usr.sites.filter((s) => s !== site) : [...usr.sites, site];
    setSavingFor(usr.username); setError("");
    try {
      const r = await api.adminSetUserSites(usr.username, next);
      setUsers((list) => list.map((x) => (x.username === usr.username ? { ...x, sites: r.sites } : x)));
    } catch (e) { setError(e.message); } finally { setSavingFor(""); }
  };

  const initials = (n) => (n || "?").slice(0, 2).toUpperCase();

  return (
    <div className="page">
      <TopNav active="reglages" user={user} onLogout={onLogout} />

      <main className="page-main">
        <div className="settings">
          {/* Sous-nav réglages */}
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
                    <div className="fc-meta">{user.role === "admin" ? "Administrateur" : "Opérateur"}</div>
                  </div>
                </div>
                <p className="fc-meta" style={{ marginTop: 14 }}>
                  Modèle d'accès : seul l'administrateur autorise les cibles et crée les
                  comptes. Chaque opérateur ne voit que les sites qui lui sont attribués.
                </p>
              </section>
            )}

            {/* ─── Utilisateurs ─── */}
            {sec === "users" && (
              <>
                <section className="fcard">
                  <div className="set-h-row">
                    <h2 className="set-h2">Utilisateurs</h2>
                    <span className="fc-meta">{users.length} compte{users.length > 1 ? "s" : ""}</span>
                  </div>
                  {loading && <div className="loading">Chargement…</div>}
                  <div className="utable">
                    <div className="ut-head"><span>Utilisateur</span><span>Rôle</span><span>Sites attribués</span><span></span></div>
                    {users.map((u) => (
                      <div key={u.username} className="ut-row">
                        <span className="ut-user">
                          <span className="ut-avatar">{initials(u.username)}</span>
                          <span>{u.username}{u.username === user.operator && <span className="fc-meta"> · vous</span>}</span>
                        </span>
                        <span><span className={`role-badge ${u.role}`}>{u.role}</span></span>
                        <span className="ut-sites">
                          {u.role === "admin" ? <span className="fc-meta">tous (non restreint)</span>
                            : u.sites.length ? u.sites.map((s) => <span key={s} className="cat">{s}</span>)
                            : <span className="fc-meta">aucun</span>}
                        </span>
                        <span className="ut-ops">
                          <button className="ghost sm" onClick={() => act(() => api.adminSetUserRole(u.username, u.role === "admin" ? "user" : "admin"), "Rôle mis à jour.")}>
                            {u.role === "admin" ? "Rétrograder" : "Promouvoir"}
                          </button>
                          <button className="ghost sm danger" disabled={u.username === user.operator}
                            onClick={() => { if (confirm(`Supprimer « ${u.username} » ?`)) act(() => api.adminDeleteUser(u.username), "Compte supprimé."); }}>
                            Supprimer
                          </button>
                        </span>
                        {u.role !== "admin" && whitelist.length > 0 && (
                          <div className="ut-acl">
                            <span className="fc-meta">Sites autorisés :</span>
                            <div className="site-checks">
                              {whitelist.map((site) => (
                                <label key={site} className="site-check">
                                  <input type="checkbox" checked={u.sites.includes(site)}
                                    disabled={savingFor === u.username} onChange={() => toggleSite(u, site)} />
                                  <span>{site}</span>
                                </label>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </section>

                <form className="fcard" onSubmit={createUser}>
                  <h2 className="set-h2">Nouvel utilisateur</h2>
                  <p className="fc-meta" style={{ marginBottom: 14 }}>L'accès sera limité aux sites cochés.</p>
                  <div className="new-user">
                    <input placeholder="Identifiant" value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} autoComplete="off" />
                    <input type="password" placeholder="Mot de passe (min. 6)" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.target.value })} autoComplete="new-password" />
                    <select value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })}>
                      <option value="user">Opérateur</option>
                      <option value="admin">Admin</option>
                    </select>
                    <button className="primary" type="submit" disabled={!nu.username.trim() || nu.password.length < 6}>Créer</button>
                  </div>
                  {nu.role !== "admin" && whitelist.length > 0 && (
                    <>
                      <div className="fld-label" style={{ marginTop: 14 }}>Sites autorisés pour ce compte</div>
                      <div className="site-checks">
                        {whitelist.map((site) => (
                          <label key={site} className="site-check">
                            <input type="checkbox" checked={nu.sites.includes(site)}
                              onChange={() => setNu((n) => ({ ...n, sites: n.sites.includes(site) ? n.sites.filter((x) => x !== site) : [...n.sites, site] }))} />
                            <span>{site}</span>
                          </label>
                        ))}
                      </div>
                    </>
                  )}
                </form>
              </>
            )}

            {/* ─── Sites autorisés ─── */}
            {sec === "sites" && (
              <section className="fcard">
                <div className="set-h-row">
                  <h2 className="set-h2">Sites autorisés</h2>
                  <span className="fc-meta">{whitelist.length} autorisé{whitelist.length > 1 ? "s" : ""}</span>
                </div>
                <p className="fc-meta" style={{ marginBottom: 14 }}>
                  Liste blanche globale (roe_policy.json). Un opérateur ne peut tester
                  qu'un site qui y figure ET qui lui est attribué.
                </p>
                <div className="utable">
                  <div className="ut-head"><span>Domaine</span><span>Opérateurs assignés</span></div>
                  {whitelist.length === 0 && <div className="fc-meta" style={{ padding: 12 }}>Aucun site dans la liste blanche.</div>}
                  {whitelist.map((site) => {
                    const ops = users.filter((u) => u.role !== "admin" && u.sites.includes(site)).map((u) => u.username);
                    return (
                      <div key={site} className="ut-row simple">
                        <span className="mono">{site}</span>
                        <span className="ut-sites">
                          {ops.length ? ops.map((o) => <span key={o} className="cat">{o}</span>) : <span className="fc-meta">aucun</span>}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}

            {/* ─── Rôles & accès (informatif) ─── */}
            {sec === "roles" && (
              <section className="fcard">
                <h2 className="set-h2">Rôles & accès</h2>
                <p className="fc-meta" style={{ marginBottom: 14 }}>
                  Séparation stricte des privilèges. Deux rôles : l'administrateur
                  gouverne, l'opérateur mène les campagnes dans les limites fixées.
                </p>
                <div className="utable">
                  <div className="ut-head"><span>Capacité</span><span>Administrateur</span><span>Opérateur</span></div>
                  {[
                    ["Créer / supprimer des comptes", "✓", "—"],
                    ["Autoriser des sites (liste blanche)", "✓", "—"],
                    ["Attribuer des sites à un opérateur", "✓", "—"],
                    ["Lancer des campagnes", "✓", "sur ses sites"],
                    ["Exploiter / confirmer à la demande", "✓", "sur ses sites"],
                  ].map((r) => (
                    <div key={r[0]} className="ut-row simple three">
                      <span>{r[0]}</span><span className="fc-meta">{r[1]}</span><span className="fc-meta">{r[2]}</span>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* ─── Préférences (informatif) ─── */}
            {sec === "prefs" && (
              <section className="fcard">
                <h2 className="set-h2">Préférences</h2>
                <ul className="pref-list">
                  <li><strong>Expiration par inactivité</strong><span className="fc-meta"> · déconnexion automatique (30 min par défaut).</span></li>
                  <li><strong>Un seul travail offensif actif par session</strong><span className="fc-meta"> · évite les actions concurrentes.</span></li>
                  <li><strong>Périmètre fermé par défaut</strong><span className="fc-meta"> · l'exploitation reste décochée au départ d'une mission.</span></li>
                  <li><strong>Vulgarisation</strong><span className="fc-meta"> · chaque faille est accompagnée d'une explication en clair.</span></li>
                  <li><strong>Rétention</strong><span className="fc-meta"> · les campagnes sont persistées sur disque et rechargées au démarrage.</span></li>
                </ul>
                <p className="fc-meta">Ces réglages reflètent la politique en vigueur côté serveur.</p>
              </section>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
