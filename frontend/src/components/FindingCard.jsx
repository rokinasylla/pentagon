import ProofTracker from "./ProofTracker.jsx";

const SEV = ["critical", "high", "medium", "low", "info"];

// Carte de faille : résumé + tracker + accès au détail et à l'exploitation.
export default function FindingCard({ finding, index, busy, onOpen, onConfirm }) {
  const sev = SEV.includes(finding.severity) ? finding.severity : "info";
  const confirmed = finding.proof_state === "confirmed";

  return (
    <article className="finding-card">
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

      <ProofTracker state={finding.proof_state} />

      <div className="fc-actions">
        <button className="link" onClick={() => onOpen(finding)}>
          Détail
        </button>
        <button
          className="primary sm"
          onClick={() => onConfirm(finding)}
          disabled={busy || confirmed}
          title={confirmed ? "Déjà confirmée" : "Démontrer l'impact réel (non destructif)"}
        >
          {confirmed ? "Confirmée ✓" : "Confirmer par exploitation"}
        </button>
      </div>
    </article>
  );
}
