import Icon from "./Icon.jsx";

// Bandeau de session (fidèle à l'artboard Main) : identité de la session active,
// pastilles du périmètre RoE, et pastille de statut. Le sélecteur de campagne
// reste discret dans le bandeau pour pouvoir changer de session.
export default function SessionHeader({ activeSession, sessions, activeId, onSelect }) {
  const hasSessions = sessions.length > 0;
  const total = activeSession
    ? (activeSession.proven_count ?? 0) + (activeSession.detected_count ?? 0)
    : 0;

  return (
    <div className="sess-band">
      <div className="sb-main">
        <span className="sb-eyebrow">Session active</span>
        <div className="sb-id">
          <select
            className="sb-switch"
            value={activeId}
            onChange={(e) => onSelect(e.target.value)}
            aria-label="Changer de session"
          >
            <option value="">{hasSessions ? "— choisir une campagne —" : "Aucune campagne"}</option>
            {sessions.map((s) => {
              const d = s.started_at ? s.started_at.slice(0, 10) : "";
              return (
                <option key={s.job_id} value={s.job_id}>
                  {s.target || s.job_id}{d && ` · ${d}`}
                </option>
              );
            })}
          </select>
          {activeSession?.target && <span className="sb-url">{activeSession.target}</span>}
        </div>
      </div>

      <div className="sb-roe">
        <span className="sb-eyebrow">Périmètre autorisé · RoE</span>
        <div className="sb-pills">
          <span className="sb-pill"><Icon name="check" size={13} sw={2.4} />Recon passive</span>
          <span className="sb-pill"><Icon name="check" size={13} sw={2.4} />Scan actif</span>
          <span className="sb-pill dashed"><Icon name="lock" size={12} />Exploitation — sur demande</span>
        </div>
      </div>

      {activeSession && (
        <div className="sb-status">
          <span className="dot" aria-hidden="true" />
          <div>
            <div className="sb-st-main">Session chargée</div>
            <div className="sb-st-sub">
              {total} faille{total > 1 ? "s" : ""} · {activeSession.proven_count ?? 0} prouvée{(activeSession.proven_count ?? 0) > 1 ? "s" : ""}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
