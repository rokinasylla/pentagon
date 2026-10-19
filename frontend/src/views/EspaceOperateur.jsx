// Accueil de l'opérateur (fidèle à l'artboard « Espace-Operateur »).
// Présentationnel : reçoit les sites attribués et les sessions récentes en
// props. Le modèle per-operator côté back (sites attribués, demandes d'accès)
// reste à créer (cf. docs/specs/ui-refonte §4) — cet écran l'accueillera.

import Icon from "../components/Icon.jsx";

// Couleur de risque d'un site.
const RISK = {
  high: { label: "Risque élevé", color: "#6E1F2E" },
  medium: { label: "Risque moyen", color: "#8A6A12" },
  low: { label: "Risque faible", color: "#3C6686" },
  none: { label: "Pas de risque", color: "#6B6F79" },
};

// Pastille de périmètre RoE : autorisée (indigo), offensive autorisée (sienne)
// ou « sur demande » (pointillés gris).
function RoePill({ label, kind }) {
  return <span className={`esp-roe ${kind}`}>{label}</span>;
}

function SiteCard({ site, onOpen, onNewMission }) {
  const risk = RISK[site.risk] || RISK.none;
  return (
    <article className="esp-card">
      <div className="esp-card-head">
        <div className="esp-card-id">
          <div className="esp-host mono">{site.host}</div>
          <div className="esp-sub">{site.subtitle}</div>
        </div>
        <span className="esp-risk" style={{ color: risk.color }}>
          <i className="swatch" style={{ background: risk.color }} />{risk.label}
        </span>
      </div>
      <div className="esp-roes">
        {(site.roe || []).map((r, i) => <RoePill key={i} label={r.label} kind={r.kind} />)}
      </div>
      <div className="esp-card-actions">
        <button className="esp-btn primary" type="button" onClick={() => onOpen && onOpen(site)}>
          Ouvrir la session <Icon name="arrow" size={14} />
        </button>
        <button className="esp-btn" type="button" onClick={() => onNewMission && onNewMission(site)}>
          Nouvelle mission
        </button>
      </div>
    </article>
  );
}

export default function EspaceOperateur({
  user = {},
  sites = [],
  sessions = [],
  onOpenSession,
  onNewMission,
  onRequestAccess,
}) {
  const firstName = user.operator || "opérateur";
  return (
    <main className="espace">
      <div className="espace-wrap">

        <div className="esp-greeting">
          <h1>Bonjour, {firstName}</h1>
          <p>
            Vous accédez uniquement aux sites que l'administrateur vous a attribués.
            Pour tester une autre cible, demandez son autorisation — l'administrateur la validera.
          </p>
        </div>

        <section>
          <div className="esp-sec-head">
            <h2>Vos sites autorisés</h2>
            <span className="esp-count">{sites.length} site{sites.length > 1 ? "s" : ""}</span>
          </div>
          <div className="esp-sites">
            {sites.map((s) => (
              <SiteCard key={s.host} site={s} onOpen={onOpenSession} onNewMission={onNewMission} />
            ))}
          </div>
          {sites.length === 0 && (
            <div className="empty">Aucun site ne vous est attribué pour l'instant.</div>
          )}
        </section>

        <section>
          <h2 className="esp-sec-title">Sessions récentes</h2>
          <div className="esp-table">
            {sessions.map((s, i) => (
              <button key={i} className="esp-row" type="button" onClick={() => onOpenSession && onOpenSession(s)}>
                <span className="esp-row-camp">
                  <span className="esp-row-title">{s.campaign}</span>
                  <span className="esp-row-target mono">{s.target}</span>
                </span>
                <span className="esp-row-state" style={{ color: s.stateColor }}>
                  <span className="dot" style={{ background: s.stateColor }} />{s.state}
                </span>
                <span className="esp-row-date">{s.date}</span>
                <span className="esp-row-open">Ouvrir <Icon name="arrow" size={14} /></span>
              </button>
            ))}
            {sessions.length === 0 && <div className="empty">Aucune session récente.</div>}
          </div>
        </section>

        <section className="esp-request">
          <div className="esp-request-txt">
            <h3>Besoin de tester un autre site ?</h3>
            <p>
              Vous ne pouvez pas ajouter de cible vous-même. Envoyez une demande :
              l'administrateur l'examine et, s'il l'autorise, le site apparaîtra ici.
            </p>
          </div>
          <button className="esp-btn" type="button" onClick={onRequestAccess}>
            <Icon name="plus" size={16} /> Demander un accès
          </button>
        </section>

      </div>
    </main>
  );
}
