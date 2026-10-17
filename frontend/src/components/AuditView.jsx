import { useEffect, useState } from "react";
import * as api from "../api/client.js";

function postureLabel(score) {
  if (score == null) return { label: "—", cls: "info" };
  if (score >= 80) return { label: "Solide", cls: "low" };
  if (score >= 50) return { label: "Correcte", cls: "medium" };
  if (score >= 25) return { label: "À renforcer", cls: "high" };
  return { label: "Critique", cls: "critical" };
}

// Répartit les contrôles en trois seaux : exposés / à corriger / conformes.
function buckets(audit) {
  const high = (s) => s === "high" || s === "critical";
  const exposes = [
    ...(audit.missing_headers || []).filter((h) => high(h.severity)).map((h) => ({
      name: h.header, detail: h.description, reco: h.owasp,
    })),
    ...(audit.info_disclosure || []).map((h) => ({
      name: h.header, detail: `expose « ${h.value} »`, reco: h.description,
    })),
  ];
  const corriger = [
    ...(audit.missing_headers || []).filter((h) => !high(h.severity)).map((h) => ({
      name: h.header, detail: h.description, reco: h.owasp,
    })),
    ...(audit.cookie_issues || []).map((c) => ({
      name: c.name || c.cookie || "cookie", detail: c.issue || c.description || "", reco: "",
    })),
  ];
  const conformes = (audit.present_headers || []).map((h) => ({
    name: h.header, detail: h.value, reco: "",
  }));
  return { exposes, corriger, conformes };
}

function Group({ title, cls, items }) {
  if (!items.length) return null;
  return (
    <section className="aud-group">
      <h4 className={`aud-gh ${cls}`}>{title} <span>{items.length}</span></h4>
      <div className="aud-items">
        {items.map((it, i) => (
          <div key={i} className="aud-item">
            <span className={`aud-dot ${cls}`} aria-hidden="true" />
            <div>
              <code className="mono">{it.name}</code>
              {(it.detail || it.reco) && (
                <div className="fc-meta">
                  {it.detail}{it.reco && ` — ${it.reco}`}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

export default function AuditView({ sessionId }) {
  const [audit, setAudit] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true); setError("");
    api.getAudit(sessionId).then(setAudit).catch((e) => setError(e.message)).finally(() => setLoading(false));
  }, [sessionId]);

  if (loading) return <div className="loading">Chargement de l'audit…</div>;
  if (error) return <div className="err">{error}</div>;
  if (!audit) return null;
  if (!audit.available) {
    return <div className="empty">Aucune donnée de durcissement pour cette session.</div>;
  }

  const p = postureLabel(audit.security_score);
  const b = buckets(audit);

  return (
    <div className="audit">
      <div className="aud-title">Hôte &amp; domaine</div>

      <div className="posture">
        <div className="posture-eyebrow">Posture globale de durcissement</div>
        <div className="posture-row">
          <span className={`posture-label ${p.cls}`}>{p.label}</span>
          <span className="posture-score">{audit.security_score ?? "—"}<span className="s-max">/100</span></span>
        </div>
        <div className="posture-counts">
          <span className="pc ok">{b.conformes.length} conformes</span>
          <span className="pc warn">{b.corriger.length} à corriger</span>
          <span className="pc bad">{b.exposes.length} exposés</span>
        </div>
      </div>

      <Group title="Exposés" cls="bad" items={b.exposes} />
      <Group title="À corriger" cls="warn" items={b.corriger} />
      <Group title="Conformes" cls="ok" items={b.conformes} />
    </div>
  );
}
