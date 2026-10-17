import ProofTracker from "./ProofTracker.jsx";
import { CATEGORY_EXPLAIN, CATEGORY_LABEL } from "../constants/categories.js";

const STAGE_LABEL = { detect: "Détection", prove: "Preuve", confirm: "Confirmation" };

// Drawer de détail d'une faille : preuve technique + explication vulgarisée +
// confiance + catégorie + historique d'évidence, et actions d'exploitation.
export default function FindingDrawer({ finding, busy, onProve, onConfirm, onRetest, onClose }) {
  if (!finding) return null;
  const confirmed = finding.proof_state === "confirmed";
  const explain = CATEGORY_EXPLAIN[finding.category];
  const catLabel = CATEGORY_LABEL[finding.category] || finding.category;

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Détail de la faille">
        <div className="drawer-head">
          <div>
            <div className="drawer-title">{finding.title}</div>
            <div className="fc-meta">
              {finding.category && <span className="cat">{catLabel}</span>}{" "}
              {finding.owasp && <span>· {finding.owasp}</span>}{" "}
              {finding.cwe && <span>· {finding.cwe}</span>}
            </div>
          </div>
          <button className="icon" onClick={onClose} aria-label="Fermer">
            ✕
          </button>
        </div>

        <div className="drawer-body">
          <ProofTracker state={finding.proof_state} />

          {finding.affected_endpoint && (
            <section className="drawer-sec">
              <h4>Endpoint concerné</h4>
              <div className="fc-endpoint">{finding.affected_endpoint}</div>
            </section>
          )}

          {explain && (
            <section className="drawer-sec">
              <h4>Ce que ça signifie</h4>
              <p>{explain}</p>
            </section>
          )}

          <section className="drawer-sec">
            <h4>Confiance</h4>
            <p>{Math.round((finding.confidence || 0) * 100)} %</p>
          </section>

          <section className="drawer-sec">
            <h4>Preuve technique</h4>
            {(!finding.evidence || finding.evidence.length === 0) && (
              <p className="muted">Aucune évidence enregistrée pour l'instant.</p>
            )}
            <ol className="evidence">
              {(finding.evidence || []).map((e, i) => (
                <li key={i}>
                  <div className="ev-head">
                    <span className={`ev-stage ${e.stage}`}>
                      {STAGE_LABEL[e.stage] || e.stage}
                    </span>
                    <span className="ev-tool">{e.tool}</span>
                  </div>
                  <code className="ev-snippet">{e.snippet}</code>
                </li>
              ))}
            </ol>
          </section>
        </div>

        <div className="drawer-actions">
          <button onClick={() => onRetest(finding)} disabled={busy}>
            Re-tester
          </button>
          <button onClick={() => onProve(finding)} disabled={busy}>
            Re-prouver
          </button>
          <button
            className="offensive"
            onClick={() => onConfirm(finding)}
            disabled={busy || confirmed}
            title={confirmed ? "Déjà confirmée" : "Démontrer l'impact réel (non destructif)"}
          >
            {confirmed ? "Confirmée ✓" : busy ? "Exploitation…" : "Confirmer par exploitation"}
          </button>
        </div>
      </aside>
    </>
  );
}
