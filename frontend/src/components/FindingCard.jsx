import ProofTracker from "./ProofTracker.jsx";

const SEV = ["critical", "high", "medium", "low", "info"];

export default function FindingCard({ finding, index }) {
  const sev = SEV.includes(finding.severity) ? finding.severity : "info";
  return (
    <article className="finding-card">
      <div className="fc-head">
        <div>
          <div className="fc-title">
            {index}. {finding.title || "Vulnérabilité"}
          </div>
          <div className="fc-meta">
            {finding.category && <span className="cat">{finding.category}</span>}{" "}
            {finding.owasp && <span>· {finding.owasp}</span>}{" "}
            {finding.cwe && <span>· {finding.cwe}</span>}
          </div>
        </div>
        <span className={`sev ${sev}`}>{sev}</span>
      </div>

      {finding.affected_endpoint && (
        <div className="fc-endpoint">{finding.affected_endpoint}</div>
      )}

      <ProofTracker state={finding.proof_state} />
    </article>
  );
}
