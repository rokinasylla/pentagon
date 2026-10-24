import ProofTracker from "./ProofTracker.jsx";
import { lastRetest } from "../utils/findings.js";

const SEV = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = {
  critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible", info: "Info",
};
// Nombre de segments remplis par niveau (rail lisible sans la couleur).
const SEV_SEG = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function confidenceLabel(c) {
  if (c == null) return "";
  if (c >= 0.85) return "confiance élevée";
  if (c >= 0.6) return "confiance moyenne";
  return "à vérifier";
}

// Dernier extrait d'évidence « preuve/confirm » → ligne de trace (réponse).
function traceResponse(finding) {
  const ev = (finding.evidence || []).filter((e) =>
    e.stage === "prove" || e.stage === "confirm" || e.stage === "detect"
  );
  return ev.length ? ev[ev.length - 1].snippet : "";
}

// Carte de faille fidèle à la maquette : trace requête→réponse, tracker et
// actions qui changent selon l'état (Détecté / Prouvé / Confirmé).
export default function FindingCard({ finding, index, acting, msg, onOpen, onProve, onConfirm, onDismiss }) {
  const sev = SEV.includes(finding.severity) ? finding.severity : "info";
  const state = finding.proof_state;
  // Faille d'observation (divulgation, en-têtes, TLS…) : déjà établie par
  // constat, rien à exploiter. Le backend expose `exploitable: false`.
  const exploitable = finding.exploitable !== false;
  const rt = lastRetest(finding);
  const resp = traceResponse(finding);
  const conf = confidenceLabel(finding.confidence);

  return (
    <article className={`finding-card ${acting ? "acting" : ""}`}>
      <div className="fc-head">
        <button className="fc-title-btn" onClick={() => onOpen(finding)}>
          <div className="fc-title">{finding.title || "Vulnérabilité"}</div>
          <div className="fc-meta">
            {finding.owasp && <span>{finding.owasp}</span>}
            {finding.cwe && <span> · {finding.cwe}</span>}
            {conf && <span> · {conf}</span>}
          </div>
        </button>
        <div className="fc-sev">
          <span className={`sev ${sev}`}>{SEV_LABEL[sev]}</span>
          <span className={`sev-rail ${sev}`} role="img" aria-label={`sévérité ${SEV_SEG[sev]} sur 5`}>
            {[0, 1, 2, 3, 4].map((i) => (
              <i key={i} className={i < SEV_SEG[sev] ? "on" : ""} />
            ))}
          </span>
        </div>
      </div>

      {/* Trace requête → réponse */}
      {(finding.affected_endpoint || resp) && (
        <div className="fc-trace">
          {finding.affected_endpoint && (
            <div className="trace-req">{finding.affected_endpoint}</div>
          )}
          {resp && <div className="trace-resp">→ {resp}</div>}
        </div>
      )}

      <div className="fc-trackline">
        <ProofTracker state={state} />
        {rt && (
          <span className={`retest-badge ${rt.resolved ? "ok" : "warn"}`}>
            {rt.resolved ? "Non reproduit" : "Toujours vulnérable"}
          </span>
        )}
      </div>

      {/* Actions selon l'état */}
      <div className="fc-actions">
        {acting && <span className="fc-wait">en cours…</span>}

        {state === "detected" && exploitable && (
          <>
            <button className="primary sm" onClick={() => onProve(finding)} disabled={acting}>
              Prouver automatiquement
            </button>
            <button className="ghost sm" onClick={() => onDismiss(finding)} disabled={acting}>
              Écarter
            </button>
          </>
        )}

        {state === "detected" && !exploitable && (
          <>
            <span className="fc-note" title="Faille établie par constat direct">
              Observation — déjà établie, rien à exploiter
            </span>
            <button className="ghost sm" onClick={() => onDismiss(finding)} disabled={acting}>
              Écarter
            </button>
          </>
        )}

        {state === "proven" && (
          <>
            <button className="link" onClick={() => onOpen(finding)} disabled={acting}>
              Revoir la preuve
            </button>
            <button className="offensive sm" onClick={() => onConfirm(finding)} disabled={acting}>
              Confirmer par exploitation
            </button>
          </>
        )}

        {state === "confirmed" && (
          <>
            <button className="link" onClick={() => onOpen(finding)} disabled={acting}>
              Revoir la preuve
            </button>
            <button className="link" onClick={() => onOpen(finding)} disabled={acting}>
              Voir la trace d'exploitation
            </button>
          </>
        )}
      </div>

      {state === "proven" && (
        <div className="fc-note">action offensive · non destructive · bornée à la preuve</div>
      )}

      {msg && <div className={`fc-result ${msg.tone}`}>{msg.text}</div>}
    </article>
  );
}
