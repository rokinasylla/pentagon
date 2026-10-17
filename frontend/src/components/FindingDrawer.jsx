import { CATEGORY_EXPLAIN, CATEGORY_LABEL } from "../constants/categories.js";

const SEV_LABEL = {
  critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible", info: "Info",
};
const STAGE = {
  detect: { label: "Détecté", cls: "detect" },
  prove: { label: "Prouvé", cls: "prove" },
  confirm: { label: "Confirmé", cls: "confirm" },
  retest: { label: "Re-test", cls: "detect" },
};
const STATE_LABEL = {
  detected: "Détecté",
  proven: "Prouvé · non destructif",
  confirmed: "Confirmé · exploitation vérifiée",
};

function hhmm(at) {
  if (!at) return "";
  const m = /T(\d{2}:\d{2})/.exec(at);
  return m ? m[1] : "";
}
function confLabel(c) {
  if (c == null) return "";
  if (c >= 0.85) return "confiance élevée";
  if (c >= 0.6) return "confiance moyenne";
  return "à vérifier";
}
function findingNumber(finding) {
  const last = String(finding.id || "").split("-").pop();
  const n = parseInt(last, 10);
  return Number.isNaN(n) ? "" : `Faille n°${n + 1}`;
}

// Détail de faille = écran « Finding-Exploitation » : en-tête + PARCOURS DE
// PREUVE (timeline de l'évidence, datée) + remédiation + actions.
export default function FindingDrawer({ finding, busy, onProve, onConfirm, onRetest, onClose }) {
  if (!finding) return null;
  const confirmed = finding.proof_state === "confirmed";
  const detected = finding.proof_state === "detected";
  const explain = CATEGORY_EXPLAIN[finding.category];
  const catLabel = CATEGORY_LABEL[finding.category] || finding.category;
  const sev = finding.severity || "info";

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Détail de la faille">
        <div className="drawer-head">
          <div>
            <div className="dh-eyebrow">
              {findingNumber(finding)}
              <span className={`state-tag ${finding.proof_state}`}>
                {STATE_LABEL[finding.proof_state] || finding.proof_state}
              </span>
            </div>
            <div className="drawer-title">{finding.title}</div>
            <div className="fc-meta">
              {finding.owasp && <span>{finding.owasp}</span>}
              {finding.cwe && <span> · {finding.cwe}</span>}
              {confLabel(finding.confidence) && <span> · {confLabel(finding.confidence)}</span>}
            </div>
          </div>
          <div className="dh-right">
            <span className={`sev ${sev}`}>{SEV_LABEL[sev] || sev}</span>
            <button className="icon" onClick={onClose} aria-label="Fermer">✕</button>
          </div>
        </div>

        <div className="drawer-body">
          {/* PARCOURS DE PREUVE */}
          <section className="drawer-sec">
            <h4>Parcours de preuve</h4>
            {(!finding.evidence || finding.evidence.length === 0) && (
              <p className="muted">Aucune étape de preuve enregistrée pour l'instant.</p>
            )}
            <ol className="journey">
              {(finding.evidence || []).map((e, i) => {
                const st = STAGE[e.stage] || { label: e.stage, cls: "detect" };
                return (
                  <li key={i} className={`jx ${st.cls}`}>
                    <div className="jx-head">
                      <span className={`ev-stage ${st.cls}`}>{st.label}</span>
                      <span className="ev-tool">{e.tool}</span>
                      {hhmm(e.at) && <span className="jx-time">· {hhmm(e.at)}</span>}
                    </div>
                    <code className="ev-snippet">{e.snippet}</code>
                  </li>
                );
              })}
            </ol>
          </section>

          {finding.affected_endpoint && (
            <section className="drawer-sec">
              <h4>Endpoint concerné</h4>
              <div className="fc-endpoint">{finding.affected_endpoint}</div>
            </section>
          )}

          {explain && (
            <section className="drawer-sec">
              <h4>Remédiation suggérée</h4>
              <p>{explain}</p>
              <p className="muted">
                Appliquer les correctifs propres à {catLabel.toLowerCase()} puis
                re-tester la faille pour vérifier qu'elle n'est plus reproductible.
              </p>
            </section>
          )}
        </div>

        <div className="drawer-actions">
          <button onClick={() => onRetest(finding)} disabled={busy}>
            Re-tester
          </button>
          {detected && (
            <button className="primary" onClick={() => onProve(finding)} disabled={busy}>
              Prouver
            </button>
          )}
          <button className="offensive" onClick={() => onConfirm(finding)} disabled={busy}>
            {confirmed ? "Rejouer la preuve" : busy ? "Exploitation…" : "Confirmer par exploitation"}
          </button>
        </div>
      </aside>
    </>
  );
}
