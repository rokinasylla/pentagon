import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import TopNav from "./components/TopNav.jsx";
import SessionHeader from "./components/SessionHeader.jsx";
import Chat from "./components/Chat.jsx";
import CommandBar from "./components/CommandBar.jsx";
import FindingCard from "./components/FindingCard.jsx";
import AuditPanel from "./components/AuditPanel.jsx";
import ReportPanel from "./components/ReportPanel.jsx";
import EspaceOperateur from "./views/EspaceOperateur.jsx";
import AdminView from "./views/AdminView.jsx";
import "./styles/tokens.css";
import "./styles/app.css";

// APERÇU — données d'exemple pour voir la Console refondue sans backend.
// Reproduit fidèlement la structure de views/Console.jsx avec les vrais
// composants et la vraie CSS.

const USER = { operator: "N. Sylla", role: "user" };

const SESSIONS = [
  { job_id: "c1", target: "acme-staging.example.com", started_at: "2026-10-17", proven_count: 2, detected_count: 1, overall_risk: "high" },
];

const MESSAGES = [
  { role: "user", text: "Fais une reconnaissance puis un scan de la cible et remonte les failles web. Reste dans le périmètre." },
  { role: "assistant", text: "J'ai cartographié la cible et lancé le scan sous le périmètre autorisé. Trois vulnérabilités sont remontées — deux déjà démontrées automatiquement, une à vérifier. Rien d'offensif n'a été déclenché." },
  { role: "user", text: "La première, c'est grave ?" },
  { role: "assistant", text: "Oui. En clair : un visiteur connecté peut lire les factures d'un autre client en changeant un simple numéro dans l'adresse. Je l'ai déjà prouvé sans rien abîmer. Si vous voulez, je peux le confirmer en montrant l'impact réel — ça reste borné à la preuve." },
  { role: "user", text: "/confirm IDOR — accès horizontal aux factures" },
  {
    role: "assistant",
    block: {
      type: "exploit",
      confirmed: true,
      title: "Confirmation par exploitation — IDOR factures",
      lead: "Exploitation pilotée comme un utilisateur réel — bornée à la preuve, sans exfiltration ni écriture destructive.",
      steps: [
        "Connexion au compte A (navigateur piloté)",
        "Appel de /invoices/10427 — ressource du compte B",
        "Facture d'un autre client affichée à l'écran",
      ],
      impact: "Lecture effective d'une facture appartenant à un autre compte. Aucune donnée exfiltrée, aucune écriture. La faille passe à Confirmé.",
    },
  },
  { role: "user", text: "/exploit 1 --sur api-admin.example.com" },
  {
    role: "assistant",
    block: {
      type: "refusal",
      title: "Action refusée — hors périmètre",
      text: "L'actif api-admin.example.com n'appartient pas au périmètre autorisé de cette mission. Le garde-fou bloque l'action avant exécution (fermé par défaut).",
    },
  },
];

const FINDINGS = [
  {
    id: "c1-0",
    title: "IDOR — accès horizontal aux factures d'un autre compte",
    severity: "critical", proof_state: "confirmed",
    owasp: "OWASP A01:2021", cwe: "CWE-639", confidence: 0.9,
    affected_endpoint: "GET /api/v1/invoices/10427 (jeton compte A)",
    evidence: [
      { stage: "detect", tool: "idor_probe", at: "2026-10-17T14:01", snippet: "/invoices/10001 → 200 · /invoices/10427 → 200 (id non lié au compte)" },
      { stage: "prove", tool: "auto", at: "2026-10-17T14:01", snippet: "200 · champ \"owner\": \"compte B\"" },
      { stage: "confirm", tool: "browser", at: "2026-10-17T14:05", snippet: "facture « ACME Nord » (compte B) · exfiltration : aucune" },
    ],
  },
  {
    id: "c1-1",
    title: "JWT — jeton forgé « alg:none » accepté par l'API",
    severity: "high", proof_state: "proven",
    owasp: "OWASP A07:2021", cwe: "CWE-347", confidence: 0.88,
    affected_endpoint: "GET /api/me",
    evidence: [
      { stage: "detect", tool: "jwt_probe", at: "2026-10-17T14:00", snippet: "en-tête alg modifiable" },
      { stage: "prove", tool: "jwt_probe", at: "2026-10-17T14:01", snippet: "200 · identité acceptée sans signature" },
    ],
  },
  {
    id: "c1-2",
    title: "SSTI — gabarit potentiellement évalué (champ « nom »)",
    severity: "medium", proof_state: "detected",
    owasp: "OWASP A03:2021", cwe: "CWE-1336", confidence: 0.4,
    affected_endpoint: "POST /profil (champ nom)",
    evidence: [
      { stage: "detect", tool: "scan", at: "2026-10-17T14:02", snippet: "nom = {{7*7}} → réfléchi tel quel, non évalué" },
    ],
  },
];

const SUGGEST = [
  "Suis-je protégé ?",
  "Explique la faille 1 simplement",
  "Lance un audit serveur",
  "Génère le rapport",
];

// --- Onglet Audit : données d'exemple (reprises de la planche Audit) ---
const AUDIT_GROUPS = [
  { title: "Transport & chiffrement", lines: [
    { name: "TLS / SSL", target: ":443", v: "bon", detail: "TLS 1.3, HSTS présent", reco: "conforme" },
    { name: "Redirection HTTP → HTTPS", target: "80 → 443", v: "bon", detail: "301 systématique", reco: "conforme" },
  ] },
  { title: "En-têtes HTTP de sécurité", lines: [
    { name: "Content-Security-Policy", target: "en-tête", v: "corriger", detail: "En-tête absent", reco: "définir une CSP restrictive" },
    { name: "X-Content-Type / Referrer-Policy", target: "en-tête", v: "corriger", detail: "Valeurs manquantes", reco: "ajouter nosniff + politique de référent" },
  ] },
  { title: "Méthodes HTTP", lines: [
    { name: "Méthodes autorisées", target: "OPTIONS *", v: "expose", detail: "TRACE et PUT activées", reco: "désactiver les méthodes non requises" },
  ] },
  { title: "Ports & services exposés", lines: [
    { name: "Surface réseau", target: "1-1000/tcp", v: "corriger", detail: "22/tcp (SSH) public", reco: "restreindre par pare-feu / bastion" },
    { name: "Services applicatifs", target: "443, 80", v: "bon", detail: "Seuls les ports web répondent", reco: "conforme" },
  ] },
  { title: "DNS & e-mail", lines: [
    { name: "SPF", target: "TXT @", v: "bon", detail: "v=spf1 -all strict", reco: "conforme" },
    { name: "DMARC", target: "_dmarc", v: "expose", detail: "Aucun enregistrement — usurpation possible", reco: "publier p=quarantine puis reject" },
    { name: "DKIM", target: "selector", v: "corriger", detail: "Clé 1024 bits", reco: "régénérer en 2048 bits" },
  ] },
  { title: "Corrélation CVE des composants", lines: [
    { name: "nginx 1.18.0", target: "bannière", v: "corriger", detail: "CVE-2021-23017", reco: "mettre à jour" },
    { name: "jQuery 1.12.4", target: "actif", v: "expose", detail: "Obsolète, XSS connus", reco: "migrer vers une version maintenue" },
  ] },
];

// --- Onglet Rapport : données d'exemple (reprises de la planche Rapport) ---
const REP_META = { target: "acme-staging", operator: "N. Sylla", date: "17 oct. 2026", campaignId: "A-2026-41", risk: "Élevé" };
const REP_STATS = { total: 3, proven: 2, confirmed: 1, owaspCovered: 7 };
const REP_SEV = [
  { key: "critical", label: "Critique", color: "#6E1F2E", n: 1 },
  { key: "high", label: "Élevée", color: "#B0541E", n: 1 },
  { key: "medium", label: "Moyenne", color: "#8A6A12", n: 1 },
  { key: "low", label: "Faible", color: "#3C6686", n: 0 },
  { key: "info", label: "Info", color: "#6B6F79", n: 0 },
];
const REP_OWASP = [
  { id: "A01", name: "Contrôle d’accès", state: "t" }, { id: "A02", name: "Défaillances crypto", state: "c" },
  { id: "A03", name: "Injection", state: "t" }, { id: "A04", name: "Conception non sûre", state: "n" },
  { id: "A05", name: "Mauvaise config.", state: "t" }, { id: "A06", name: "Composants vulnérables", state: "t" },
  { id: "A07", name: "Auth. défaillante", state: "t" }, { id: "A08", name: "Intégrité logicielle", state: "n" },
  { id: "A09", name: "Journalisation", state: "n" }, { id: "A10", name: "SSRF", state: "c" },
];
const REP_FINDINGS = [
  { severity: "critical", title: "IDOR — factures d’un autre compte", cat: "A01 · CWE-639", state: "confirmed" },
  { severity: "high", title: "JWT — jeton « alg:none » accepté", cat: "A07 · CWE-347", state: "proven" },
  { severity: "medium", title: "SSTI — gabarit potentiellement évalué", cat: "A03 · CWE-1336", state: "detected" },
];
const REP_ACTIONS = (
  <>
    <button className="rep-btn primary" type="button">Exporter en PDF</button>
    <button className="rep-btn" type="button">Partager un lien</button>
  </>
);

// --- Espace opérateur : données d'exemple (reprises de la planche) ---
const ESP_SITES = [
  {
    host: "acme-staging.example.com",
    subtitle: "campagne active #A-2026-41 · dernière session aujourd'hui",
    risk: "high",
    roe: [{ label: "Recon", kind: "on" }, { label: "Scan actif", kind: "on" }, { label: "Exploitation sur demande", kind: "dashed" }],
  },
  {
    host: "shop.acme.io",
    subtitle: "campagne #A-2026-38 · dernière session 02 oct.",
    risk: "medium",
    roe: [{ label: "Recon", kind: "on" }, { label: "Scan actif", kind: "on" }, { label: "Exploitation", kind: "offensive" }],
  },
];
const ESP_SESSIONS = [
  { campaign: "Campagne #A-2026-41", target: "acme-staging.example.com", state: "En cours", stateColor: "#B0541E", date: "aujourd'hui" },
  { campaign: "Campagne #A-2026-38", target: "shop.acme.io", state: "Terminée", stateColor: "#3C6686", date: "02 oct. 2026" },
  { campaign: "Campagne #A-2026-29", target: "acme-staging.example.com", state: "Terminée", stateColor: "#3C6686", date: "10 sept. 2026" },
];

// --- Administration : données d'exemple (reprises de la planche Admin) ---
const ADMIN_USER = { operator: "A. Diop", email: "a.diop@acme-sec.io", role: "admin" };
const ADMIN_USERS = [
  { initials: "AD", name: "A. Diop", email: "a.diop@acme-sec.io", role: "admin", sites: "Tous les sites", status: "actif", statusLabel: "Actif" },
  { initials: "NS", name: "N. Sylla", email: "n.sylla@acme-sec.io", role: "op", sites: "acme-staging, shop.acme.io", status: "actif", statusLabel: "Actif" },
  { initials: "MF", name: "M. Fall", email: "m.fall@acme-sec.io", role: "op", sites: "api.acme.io", status: "invite", statusLabel: "Invité" },
  { initials: "JB", name: "J. Ba", email: "j.ba@acme-sec.io", role: "op", sites: "Aucun site", status: "suspendu", statusLabel: "Suspendu" },
];
const ADMIN_SITES = [
  { domain: "acme-staging.example.com", by: "A. Diop", date: "12 sept.", operator: "N. Sylla", scope: "recon · scan", status: "autorise", statusLabel: "Autorisé" },
  { domain: "shop.acme.io", by: "A. Diop", date: "28 sept.", operator: "N. Sylla", scope: "recon · scan · exploit", status: "autorise", statusLabel: "Autorisé" },
  { domain: "api.acme.io", by: "A. Diop", date: "01 oct.", operator: "M. Fall", scope: "recon · scan", status: "autorise", statusLabel: "Autorisé" },
  { domain: "intranet.acme.local", by: "— demande opérateur", date: "15 oct.", operator: "N. Sylla", scope: "à définir", status: "attente", statusLabel: "En attente" },
  { domain: "old.acme.io", by: "A. Diop", date: "03 août", operator: "—", scope: "—", status: "revoque", statusLabel: "Révoqué" },
];
const ADMIN_OPERATORS = ["N. Sylla", "M. Fall"];
const ADMIN_SITEOPTS = ["acme-staging.example.com", "shop.acme.io", "api.acme.io"];
const _yes = { yes: true }, _no = { no: true };
const _note = (t, tone) => ({ note: true, noteTxt: t, tone });
const ADMIN_CAPS = [
  { label: "Autoriser / révoquer des sites", admin: _yes, op: _no },
  { label: "Créer et gérer les comptes", admin: _yes, op: _no },
  { label: "Définir les rôles & droits", admin: _yes, op: _no },
  { label: "Voir tous les sites & campagnes", admin: _yes, op: _note("ses sites", "warn") },
  { label: "Reconnaissance & scan", admin: _yes, op: _note("ses sites", "warn") },
  { label: "Exploitation à la demande", admin: _yes, op: _note("si RoE", "warn") },
  { label: "Générer & exporter un rapport", admin: _yes, op: _yes },
  { label: "Étendre le périmètre (RoE)", admin: _yes, op: _note("sur demande", "warn") },
];

function PreviewConsole() {
  const [tab, setTab] = useState("findings");
  const noop = () => {};

  return (
    <div className="page">
      <TopNav active="sessions" user={USER} onLogout={noop} />
      <SessionHeader activeSession={SESSIONS[0]} sessions={SESSIONS} activeId="c1" onSelect={noop} />

      <div className="workspace">
        <section className="conv">
          <div className="conv-scroll">
            <Chat messages={MESSAGES} userInitials="NS" />
          </div>
          <div className="composer">
            <div className="composer-chips">
              {SUGGEST.map((s) => (
                <button key={s} className="chip" type="button" onClick={noop}>{s}</button>
              ))}
            </div>
            <CommandBar onSubmit={noop} busy={false} />
            <div className="composer-hint">
              ⌘⏎ envoyer · / affiche les commandes — /scan /exploit /confirm /audit /report /scope /stop
            </div>
          </div>
        </section>

        <section className="canvas">
          <div className="canvas-tabs" role="tablist">
            <button className={`ctab ${tab === "findings" ? "on" : ""}`} onClick={() => setTab("findings")}>
              Findings <span className="tab-n">3</span>
            </button>
            <button className={`ctab ${tab === "audit" ? "on" : ""}`} onClick={() => setTab("audit")}>Audit</button>
            <button className={`ctab ${tab === "report" ? "on" : ""}`} onClick={() => setTab("report")}>Rapport</button>
            {tab === "findings" && <span className="canvas-sort">Tri : sévérité ↓</span>}
          </div>
          <div className="canvas-body">
            {tab === "findings" && (
              <div className="findings">
                {FINDINGS.map((f, i) => (
                  <FindingCard key={f.id} finding={f} index={i + 1} acting={false} msg={null}
                    onOpen={noop} onProve={noop} onConfirm={noop} onDismiss={noop} />
                ))}
              </div>
            )}
            {tab === "audit" && <AuditPanel score={42} groups={AUDIT_GROUPS} />}
            {tab === "report" && (
              <ReportPanel meta={REP_META} stats={REP_STATS} sev={REP_SEV}
                owasp={REP_OWASP} findings={REP_FINDINGS} actions={REP_ACTIONS} />
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

function EspacePreview() {
  const noop = () => {};
  return (
    <div className="page">
      <TopNav active="accueil" user={USER} onLogout={noop} />
      <EspaceOperateur
        user={USER}
        sites={ESP_SITES}
        sessions={ESP_SESSIONS}
        onOpenSession={noop}
        onNewMission={noop}
        onRequestAccess={noop}
      />
    </div>
  );
}

function AdminPreview() {
  const noop = () => {};
  return (
    <div className="page">
      <TopNav active="reglages" user={ADMIN_USER} onLogout={noop} />
      <AdminView
        user={ADMIN_USER}
        initialSection="sites"
        users={ADMIN_USERS}
        sites={ADMIN_SITES}
        operators={ADMIN_OPERATORS}
        siteOptions={ADMIN_SITEOPTS}
        caps={ADMIN_CAPS}
        onCreateUser={noop}
        onAuthorizeSite={noop}
      />
    </div>
  );
}

// Petit sélecteur de vue (hors app) pour parcourir les écrans refondus.
const SWITCH = { position: "fixed", top: 8, left: "50%", transform: "translateX(-50%)", zIndex: 50, display: "flex", gap: 4, background: "rgba(20,24,29,.9)", padding: 4, borderRadius: 999, boxShadow: "0 4px 16px rgba(0,0,0,.25)" };
const SW_BTN = (on) => ({ all: "unset", cursor: "pointer", fontSize: 12, fontWeight: 600, color: on ? "#16181d" : "#f4f3ee", background: on ? "#f4f3ee" : "transparent", borderRadius: 999, padding: "5px 13px" });

const VIEWS = { console: PreviewConsole, espace: EspacePreview, admin: AdminPreview };

function Preview() {
  const [view, setView] = useState("console");
  const Current = VIEWS[view];
  return (
    <>
      <div style={SWITCH}>
        <button style={SW_BTN(view === "console")} onClick={() => setView("console")}>Console</button>
        <button style={SW_BTN(view === "espace")} onClick={() => setView("espace")}>Espace opérateur</button>
        <button style={SW_BTN(view === "admin")} onClick={() => setView("admin")}>Admin</button>
      </div>
      <Current />
    </>
  );
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <MemoryRouter>
      <Preview />
    </MemoryRouter>
  </React.StrictMode>
);
