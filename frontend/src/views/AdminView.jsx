// Administration — 5 sections per-operator (fidèle à l'artboard « Admin »).
// Présentationnel : reçoit comptes, sites attribués, matrice de droits et
// préférences en props, plus des handlers. Le modèle per-operator côté back
// (affectation site→opérateur, périmètre max, preuve, demandes d'accès) reste
// à créer (cf. docs/specs/ui-refonte §4) ; cet écran est prêt à l'accueillir.

import { useState } from "react";

const RAIL = [
  { id: "account", label: "Mon compte", icon: (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="8" r="3.4" stroke="currentColor" strokeWidth="1.8" /><path d="M5 20c1.2-3.6 4-5 7-5s5.8 1.4 7 5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>
  ) },
  { id: "users", label: "Utilisateurs", icon: (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="9" cy="9" r="3" stroke="currentColor" strokeWidth="1.8" /><path d="M3.5 19c.9-3 3-4.2 5.5-4.2S13.6 16 14.5 19" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /><path d="M16 7a3 3 0 010 6M17 19c-.2-1.7-.8-3-1.7-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>
  ) },
  { id: "sites", label: "Sites autorisés", icon: (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8" /><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" stroke="currentColor" strokeWidth="1.6" /></svg>
  ) },
  { id: "roles", label: "Rôles & accès", icon: (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3l7 3v5c0 4.2-2.8 7.6-7 9-4.2-1.4-7-4.8-7-9V6l7-3z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" /></svg>
  ) },
  { id: "prefs", label: "Préférences", icon: (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="3.2" stroke="currentColor" strokeWidth="1.8" /><path d="M12 4v2M12 18v2M4 12h2M18 12h2M6.5 6.5l1.5 1.5M16 16l1.5 1.5M17.5 6.5L16 8M8 16l-1.5 1.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>
  ) },
];

const ROLE_BADGE = {
  admin: { color: "#2E3A59", bg: "#EDEFF4", border: "#D7DCEA" },
  op: { color: "#55596A", bg: "#F4F3EE", border: "#DEDBD2" },
};
const USER_STATUS = {
  actif: { color: "#3C6686", dot: "#3C6686" },
  invite: { color: "#8A6A12", dot: "#C79A2E" },
  suspendu: { color: "#6E1F2E", dot: "#9E5560" },
};
const SITE_STATUS = {
  autorise: { color: "#3C6686", dot: "#3C6686" },
  attente: { color: "#8A6A12", dot: "#C79A2E" },
  revoque: { color: "#6E1F2E", dot: "#9E5560" },
};

function Toggle({ on }) {
  return <span className={`av-sw ${on ? "on" : ""}`} aria-hidden="true"><i /></span>;
}

function Account({ user }) {
  const initials = (user.operator || "AD").slice(0, 2).toUpperCase();
  return (
    <>
      <h1 className="av-h1">Mon compte</h1>
      <div className="av-cols">
        <section className="av-card av-grow">
          <div className="av-acct">
            <span className="av-acct-av">{initials}</span>
            <div><div className="av-acct-name">{user.operator || "A. Diop"}</div><div className="av-acct-mail mono">{user.email || "a.diop@acme-sec.io"}</div></div>
            <span className="av-role-badge admin">Administrateur</span>
          </div>
          <div className="av-sep">
            <label className="av-field-wrap"><span className="av-label">Nom affiché</span><span className="av-field"><input defaultValue={user.operator || "A. Diop"} /></span></label>
            <label className="av-field-wrap"><span className="av-label">Mot de passe</span><span className="av-field"><input type="password" defaultValue="············" /><button type="button" className="av-chip-btn">Modifier</button></span></label>
          </div>
          <button type="button" className="av-btn primary av-self">Enregistrer</button>
        </section>
        <section className="av-card">
          <h2 className="av-h2">Sécurité</h2>
          <div className="av-row-sw"><div><div className="av-sw-t">Double authentification</div><div className="av-sw-d">Obligatoire pour les administrateurs</div></div><Toggle on /></div>
          <div className="av-note-line av-sep-top">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ color: "#3C6686" }}><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8" /><path d="M8 12l2.5 2.5L16 9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
            Dernière connexion : aujourd'hui, 14:58 · Reykjavik
          </div>
          <button type="button" className="av-btn danger av-self">Se déconnecter</button>
        </section>
      </div>
    </>
  );
}

function Users({ users, siteOptions, onCreateUser }) {
  return (
    <>
      <div className="av-h-row"><h1 className="av-h1">Utilisateurs</h1><span className="av-count">{users.length} comptes</span></div>
      <div className="av-cols">
        <section className="av-card flush av-grow">
          <div className="av-thead" style={{ gridTemplateColumns: "2fr 1.1fr 1.6fr 1fr" }}>
            <span>Utilisateur</span><span>Rôle</span><span>Sites attribués</span><span>Statut</span>
          </div>
          {users.map((u, i) => {
            const st = USER_STATUS[u.status] || USER_STATUS.actif;
            return (
              <div key={i} className="av-trow" style={{ gridTemplateColumns: "2fr 1.1fr 1.6fr 1fr" }}>
                <span className="av-u">
                  <span className="av-u-av" style={{ background: u.role === "admin" ? "#2E3A59" : "#16181D" }}>{u.initials}</span>
                  <span className="av-u-id"><span className="av-u-name">{u.name}</span><span className="av-u-mail mono">{u.email}</span></span>
                </span>
                <span><span className="av-role-badge" style={{ color: ROLE_BADGE[u.role].color, background: ROLE_BADGE[u.role].bg, border: `1px solid ${ROLE_BADGE[u.role].border}` }}>{u.role === "admin" ? "Administrateur" : "Opérateur"}</span></span>
                <span className="av-u-sites">{u.sites}</span>
                <span className="av-status" style={{ color: st.color }}><i className="dot" style={{ background: st.dot }} />{u.statusLabel}</span>
              </div>
            );
          })}
        </section>

        <section className="av-card">
          <h2 className="av-h2 icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ color: "#2E3A59" }}><circle cx="10" cy="9" r="3.2" stroke="currentColor" strokeWidth="1.8" /><path d="M4 19c.9-3 3.2-4.3 6-4.3" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /><path d="M17 14v6M14 17h6" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" /></svg>
            Nouvel utilisateur
          </h2>
          <p className="av-card-sub">L'accès sera limité aux sites cochés.</p>
          <form className="av-form" onSubmit={(e) => { e.preventDefault(); onCreateUser && onCreateUser(); }}>
            <label className="av-field-wrap"><span className="av-label">Nom complet</span><span className="av-field"><input placeholder="Prénom Nom" /></span></label>
            <label className="av-field-wrap"><span className="av-label">E-mail</span><span className="av-field"><input type="email" className="mono" placeholder="nom@organisation.fr" /></span></label>
            <div>
              <span className="av-label">Rôle</span>
              <div className="av-radios">
                <label className="av-radio on"><input type="radio" name="role" defaultChecked />Opérateur</label>
                <label className="av-radio"><input type="radio" name="role" />Admin</label>
              </div>
            </div>
            <div>
              <span className="av-label">Sites autorisés pour ce compte</span>
              <div className="av-checks">
                {siteOptions.map((s, i) => (
                  <label key={s} className="av-check"><input type="checkbox" defaultChecked={i === 0} /><span className="mono">{s}</span></label>
                ))}
              </div>
            </div>
            <button type="submit" className="av-btn primary block">Créer et inviter</button>
            <p className="av-fine">Un e-mail d'invitation permet à l'utilisateur de définir son mot de passe.</p>
          </form>
        </section>
      </div>
    </>
  );
}

function Sites({ sites, operators, onAuthorizeSite }) {
  return (
    <>
      <div className="av-h-row"><h1 className="av-h1">Sites autorisés</h1><span className="av-count">{sites.filter((s) => s.status === "autorise").length} autorisés · {sites.filter((s) => s.status === "attente").length} en attente</span></div>
      <div className="av-cols">
        <section className="av-card flush av-grow">
          <div className="av-thead" style={{ gridTemplateColumns: "1.9fr 1.3fr 1.5fr 1fr" }}>
            <span>Domaine</span><span>Opérateur</span><span>Périmètre max</span><span>Statut</span>
          </div>
          {sites.map((s, i) => {
            const st = SITE_STATUS[s.status] || SITE_STATUS.autorise;
            return (
              <div key={i} className="av-trow" style={{ gridTemplateColumns: "1.9fr 1.3fr 1.5fr 1fr" }}>
                <span className="av-u-id"><span className="av-u-name mono">{s.domain}</span><span className="av-site-by">autorisé par {s.by} · {s.date}</span></span>
                <span className="av-u-sites">{s.operator}</span>
                <span className="av-scope mono">{s.scope}</span>
                <span className="av-status" style={{ color: st.color }}><i className="dot" style={{ background: st.dot }} />{s.statusLabel}</span>
              </div>
            );
          })}
        </section>

        <section className="av-card">
          <h2 className="av-h2 icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ color: "#2E3A59" }}><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8" /><path d="M8 12l2.5 2.5L16 9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
            Autoriser un site
          </h2>
          <p className="av-card-sub">Le site devient testable, dans la limite du périmètre que vous fixez.</p>
          <form className="av-form" onSubmit={(e) => { e.preventDefault(); onAuthorizeSite && onAuthorizeSite(); }}>
            <label className="av-field-wrap"><span className="av-label">Domaine / URL</span><span className="av-field"><input className="mono" placeholder="exemple.com" /></span></label>
            <label className="av-field-wrap"><span className="av-label">Preuve d'autorisation</span><span className="av-field"><select><option>Mandat signé</option><option>Propriétaire vérifié</option><option>Périmètre bug bounty</option></select></span></label>
            <div>
              <span className="av-label">Périmètre maximal autorisé</span>
              <div className="av-checks">
                <label className="av-check"><input type="checkbox" defaultChecked />Reconnaissance passive</label>
                <label className="av-check"><input type="checkbox" defaultChecked />Scan actif</label>
                <label className="av-check dashed"><input type="checkbox" />Exploitation</label>
              </div>
            </div>
            <label className="av-field-wrap"><span className="av-label">Opérateur assigné</span><span className="av-field"><select>{operators.map((o) => <option key={o}>{o}</option>)}</select></span></label>
            <button type="submit" className="av-btn primary block">Autoriser le site</button>
            <div className="av-warn">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ color: "#B0541E", flexShrink: 0, marginTop: 1 }}><path d="M12 3l9 16H3l9-16z" stroke="currentColor" strokeWidth="1.9" strokeLinejoin="round" /><path d="M12 10v4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /><circle cx="12" cy="16.4" r="1" fill="currentColor" /></svg>
              <p>En autorisant, vous attestez disposer du droit légal de faire tester cette cible.</p>
            </div>
          </form>
        </section>
      </div>
    </>
  );
}

function Roles({ caps }) {
  const Cell = ({ c }) => {
    if (c.note) return <span className={`av-cap-note ${c.tone || ""}`}>{c.noteTxt}</span>;
    if (c.yes) return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-label="autorisé" role="img" style={{ color: "#3C6686" }}><path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    return <span className="av-cap-no">—</span>;
  };
  return (
    <>
      <h1 className="av-h1">Rôles & accès</h1>
      <p className="av-lead">Séparation stricte des privilèges. Deux rôles seulement : l'administrateur gouverne, l'opérateur mène les campagnes dans les limites qu'on lui fixe.</p>
      <section className="av-card flush av-mb">
        <div className="av-thead center" style={{ gridTemplateColumns: "2fr 1fr 1fr" }}>
          <span>Capacité</span><span className="c-admin">Administrateur</span><span className="c-op">Opérateur</span>
        </div>
        {caps.map((c, i) => (
          <div key={i} className="av-trow" style={{ gridTemplateColumns: "2fr 1fr 1fr" }}>
            <span className="av-cap-label">{c.label}</span>
            <span className="av-cap-cell"><Cell c={c.admin} /></span>
            <span className="av-cap-cell"><Cell c={c.op} /></span>
          </div>
        ))}
      </section>
      <section className="av-card">
        <h2 className="av-h2">Sécurité des sessions</h2>
        <div className="av-row-sw"><div className="av-grow"><div className="av-sw-t">Expiration par inactivité</div><div className="av-sw-d">Déconnexion automatique après une période d'inactivité.</div></div><span className="av-field sel"><select defaultValue="30"><option value="15">15 minutes</option><option value="30">30 minutes</option><option value="60">1 heure</option></select></span></div>
        <div className="av-row-sw av-sep-top"><div className="av-grow"><div className="av-sw-t">Double authentification obligatoire (admins)</div><div className="av-sw-d">Renforce l'accès aux fonctions de gouvernance.</div></div><Toggle on /></div>
        <div className="av-row-sw av-sep-top"><div className="av-grow"><div className="av-sw-t">Un seul travail offensif actif par session</div><div className="av-sw-d">Évite les actions concurrentes non maîtrisées.</div></div><Toggle on /></div>
      </section>
    </>
  );
}

function Prefs() {
  return (
    <>
      <h1 className="av-h1">Préférences</h1>
      <section className="av-card av-mb" style={{ gap: 20 }}>
        <div>
          <div className="av-sw-t">Moteur d'orchestration par défaut</div>
          <div className="av-sw-d mb">Appliqué aux nouvelles missions ; modifiable mission par mission.</div>
          <div className="av-engine">
            <label className="av-eng on"><input type="radio" name="eng" defaultChecked /><span><strong>Séquentiel</strong> <span className="av-eng-tag">· défaut</span><span className="av-eng-d">Phases l'une après l'autre, lisible.</span></span></label>
            <label className="av-eng"><input type="radio" name="eng" /><span><strong>Graphe parallèle</strong><span className="av-eng-d">Branches concurrentes (LangGraph).</span></span></label>
          </div>
        </div>
        <div className="av-sep-top">
          <div className="av-sw-t">Périmètre par défaut d'une nouvelle mission</div>
          <div className="av-sw-d mb">Fermé par défaut — l'exploitation reste toujours décochée au départ.</div>
          <div className="av-checks row">
            <label className="av-check"><input type="checkbox" defaultChecked />Reconnaissance passive</label>
            <label className="av-check"><input type="checkbox" defaultChecked />Scan actif</label>
            <label className="av-check dashed"><input type="checkbox" />Exploitation</label>
          </div>
        </div>
      </section>
      <section className="av-card av-mb">
        <h2 className="av-h2">Agent & restitution</h2>
        <div className="av-row-sw"><div className="av-grow"><div className="av-sw-t">Vulgariser pour les non-experts</div><div className="av-sw-d">L'agent accompagne chaque faille d'une explication en clair.</div></div><Toggle on /></div>
        <div className="av-row-sw av-sep-top"><div className="av-grow"><div className="av-sw-t">Notifier les failles critiques confirmées</div><div className="av-sw-d">Alerte à chaque passage à l'état Confirmé.</div></div><Toggle on /></div>
        <div className="av-row-sw av-sep-top"><div className="av-grow"><div className="av-sw-t">Notifier la fin de campagne</div><div className="av-sw-d">Résumé envoyé à l'opérateur et à l'admin.</div></div><Toggle /></div>
      </section>
      <section className="av-card row av-mb">
        <div className="av-grow"><div className="av-sw-t">Rétention des campagnes</div><div className="av-sw-d">Les campagnes sont persistées sur disque et rechargées au démarrage.</div></div>
        <span className="av-field sel"><select><option>Conserver indéfiniment</option><option>90 jours</option><option>1 an</option></select></span>
      </section>
      <button type="button" className="av-btn primary">Enregistrer les préférences</button>
    </>
  );
}

export default function AdminView({
  user = {},
  initialSection = "sites",
  users = [],
  sites = [],
  operators = [],
  siteOptions = [],
  caps = [],
  onCreateUser,
  onAuthorizeSite,
}) {
  const [sec, setSec] = useState(initialSection);
  return (
    <main className="adminv">
      <aside className="av-rail">
        <div className="av-rail-eyebrow">Réglages</div>
        {RAIL.map((r) => (
          <button key={r.id} className={`av-link ${sec === r.id ? "on" : ""}`} onClick={() => setSec(r.id)}>
            {r.icon}{r.label}
          </button>
        ))}
      </aside>
      <div className="av-main">
        <div className="av-content">
          <div className="av-banner">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ color: "#2E3A59", flexShrink: 0, marginTop: 1 }}><path d="M12 3l7 3v5c0 4.2-2.8 7.6-7 9-4.2-1.4-7-4.8-7-9V6l7-3z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" /><path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
            <p><strong>Modèle d'accès.</strong> Seul l'administrateur autorise les cibles et crée les comptes. Chaque opérateur ne voit, après connexion, que les sites qui lui sont attribués — il ne peut pas en autoriser de nouveaux, il en fait la demande et vous validez.</p>
          </div>

          {sec === "account" && <Account user={user} />}
          {sec === "users" && <Users users={users} siteOptions={siteOptions} onCreateUser={onCreateUser} />}
          {sec === "sites" && <Sites sites={sites} operators={operators} onAuthorizeSite={onAuthorizeSite} />}
          {sec === "roles" && <Roles caps={caps} />}
          {sec === "prefs" && <Prefs />}
        </div>
      </div>
    </main>
  );
}
