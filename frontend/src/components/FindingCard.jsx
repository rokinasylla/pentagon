import ProofTracker from "./ProofTracker.jsx";
import { lastRetest } from "../utils/findings.js";

const SEV = ["critical", "high", "medium", "low", "info"];

// Carte de faille : résumé + tracker + accès au détail, exploitation et re-test.
export default function FindingCard({ finding, index, acting, onOpen, onConfirm, onRetest }) {
  const sev = SEV.includes(finding.severity) ? finding.severity : "info";
  const confirmed = finding.proof_state === "confirmed";
  const rt = lastRetest(finding);

  return (
    <article className={`finding-card ${acting ? "acting" : ""}`}>
      <div className="fc-head">
        <button className="fc-title-btn" onClick={() => onOpen(finding)}>
          <div className="fc-title">
            {index}. {finding.title || "Vulnérabilité"}
          </div>
          <div className="fc-meta">
            {finding.category && <span className="cat">{finding.category}</span>}{" "}
            {finding.owasp && <span>· {finding.owasp}</span>}{" "}
            {finding.cwe && <span>· {finding.cwe}</span>}
          </div>
        </button>
        <span className={`sev ${sev}`}>{sev}</span>
      </div>

      {finding.affected_endpoint && (
        <div className="fc-endpoint">{finding.affected_endpoint}</div>
      )}

      <div className="fc-trackline">
        <ProofTracker state={finding.proof_state} />
        {rt && (
          <span className={`retest-badge ${rt.resolved ? "ok" : "warn"}`}>
            {rt.resolved ? "Non reproduit" : "Toujours vulnérable"}
          </span>
        )}
      </div>

      <div className="fc-actions">
        {acting && <span className="fc-wait">en cours…</span>}
        <button className="link" onClick={() => onOpen(finding)} disabled={acting}>
          Détail
        </button>
        <button className="ghost sm" onClick={() => onRetest(finding)} disabled={acting}>
          Re-tester
        </button>
        <button
          className="offensive sm"
          onClick={() => onConfirm(finding)}
          disabled={acting || confirmed}
          title={confirmed ? "Déjà confirmée" : "Démontrer l'impact réel (non destructif)"}
        >
          {confirmed ? "Confirmée ✓" : "Confirmer par exploitation"}
        </button>
      </div>
    </article>
  );
}
