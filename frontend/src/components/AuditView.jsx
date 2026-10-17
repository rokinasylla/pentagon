import { useEffect, useState } from "react";
import * as api from "../api/client.js";

const SEV = ["critical", "high", "medium", "low", "info"];
const sevClass = (s) => (SEV.includes(s) ? s : "info");

// Note de durcissement → libellé + teinte (réutilise les tokens de sévérité).
function scoreTone(score) {
  if (score == null) return { label: "—", cls: "info" };
  if (score >= 80) return { label: "Bon", cls: "low" };
  if (score >= 50) return { label: "Moyen", cls: "medium" };
  if (score >= 25) return { label: "Faible", cls: "high" };
  return { label: "Critique", cls: "critical" };
}

export default function AuditView({ sessionId }) {
  const [audit, setAudit] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true);
    setError("");
    api
      .getAudit(sessionId)
      .then(setAudit)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [sessionId]);

  if (loading) return <div className="loading">Chargement de l'audit…</div>;
  if (error) return <div className="err">{error}</div>;
  if (!audit) return null;
  if (!audit.available) {
    return (
      <div className="empty">
        Aucune donnée de durcissement pour cette session (l'analyse des en-têtes
        n'a pas été exécutée).
      </div>
    );
  }

  const tone = scoreTone(audit.security_score);

  return (
    <div className="audit">
      <div className="audit-score">
        <div className={`score-badge ${tone.cls}`}>
          <span className="score-num">
            {audit.security_score ?? "—"}
            <span className="score-max">/100</span>
          </span>
          <span className="score-label">{tone.label}</span>
        </div>
        <div className="audit-score-meta">
          <div className="audit-title">Posture de durcissement</div>
          <div className="fc-meta">
            {audit.target} · HTTP {audit.http_status ?? "?"} · risque global{" "}
            {audit.overall_risk}
          </div>
        </div>
      </div>

      <AuditSection
        title={`En-têtes de sécurité manquants (${audit.missing_headers.length})`}
        empty="Aucun en-tête de sécurité manquant."
        items={audit.missing_headers}
        render={(h) => (
          <div className="audit-row">
            <div>
              <code className="mono">{h.header}</code>
              <div className="fc-meta">
                {h.description} {h.owasp && `· ${h.owasp}`}
              </div>
            </div>
            <span className={`sev ${sevClass(h.severity)}`}>{h.severity}</span>
          </div>
        )}
      />

      <AuditSection
        title={`Fuites d'information (${audit.info_disclosure.length})`}
        empty="Aucun en-tête divulguant d'information."
        items={audit.info_disclosure}
        render={(h) => (
          <div className="audit-row">
            <div>
              <code className="mono">
                {h.header}: {h.value}
              </code>
              <div className="fc-meta">{h.description}</div>
            </div>
          </div>
        )}
      />

      <AuditSection
        title={`Problèmes de cookies (${audit.cookie_issues.length})`}
        empty="Aucun problème de cookie détecté."
        items={audit.cookie_issues}
        render={(c) => (
          <div className="audit-row">
            <code className="mono">{c.name || c.cookie || JSON.stringify(c)}</code>
            <span className="fc-meta">{c.issue || c.description || ""}</span>
          </div>
        )}
      />

      <AuditSection
        title={`En-têtes de sécurité présents (${audit.present_headers.length})`}
        empty="Aucun en-tête de sécurité présent."
        items={audit.present_headers}
        render={(h) => (
          <div className="audit-row ok">
            <code className="mono">
              {h.header}: {h.value}
            </code>
            <span className="audit-check" aria-hidden="true">✓</span>
          </div>
        )}
      />
    </div>
  );
}

function AuditSection({ title, items, empty, render }) {
  return (
    <section className="audit-sec">
      <h4>{title}</h4>
      {items.length === 0 ? (
        <p className="audit-empty">{empty}</p>
      ) : (
        <div className="audit-list">
          {items.map((it, i) => (
            <div key={i} className="audit-item">
              {render(it)}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
