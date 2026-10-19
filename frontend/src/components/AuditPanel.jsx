// Panneau présentationnel de l'onglet Audit (fidèle à la planche Audit.dc.html).
// Pur : ne fait aucun appel réseau. Reçoit des groupes de contrôles déjà
// normalisés et en dérive la posture globale. Réutilisé tel quel par le
// conteneur AuditView (données API) et par l'aperçu (données d'exemple).

// Palette des verdicts (charte PENTAGON).
const VERDICT = {
  bon: { label: "Conforme", color: "#3C6686", bg: "#EEF3F7", border: "#D3E0EA", seg: "#9FB6C8" },
  corriger: { label: "À corriger", color: "#8A6A12", bg: "#FBF4E0", border: "#ECDFBD", seg: "#E3C77A" },
  expose: { label: "Exposé", color: "#6E1F2E", bg: "#F7EAEC", border: "#E7C9CE", seg: "#C98B94" },
};

// Icône de verdict (trait, 12px) — la sévérité n'est jamais portée par la
// seule couleur : un pictogramme accompagne chaque pastille.
function VerdictIcon({ v }) {
  if (v === "bon") {
    return (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  if (v === "corriger") {
    return (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M12 4l9 16H3l9-16z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
        <path d="M12 10v4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    );
  }
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" />
      <path d="M12 7v5" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
      <circle cx="12" cy="16" r="1.2" fill="currentColor" />
    </svg>
  );
}

// Posture globale dérivée du score de durcissement (/100).
function posture(score) {
  if (score == null) return { label: "—", color: "#6B6F79" };
  if (score >= 80) return { label: "Solide", color: "#3C6686" };
  if (score >= 50) return { label: "Correcte", color: "#3C6686" };
  if (score >= 25) return { label: "À renforcer", color: "#8A6A12" };
  return { label: "Critique", color: "#6E1F2E" };
}

export default function AuditPanel({ score, groups = [], scope = "Hôte & domaine" }) {
  // Comptage des verdicts sur l'ensemble des lignes.
  let bon = 0, corriger = 0, expose = 0;
  for (const g of groups) {
    for (const l of g.lines) {
      if (l.v === "bon") bon++;
      else if (l.v === "corriger") corriger++;
      else expose++;
    }
  }
  const p = posture(score);

  return (
    <div className="audit-panel">
      {/* POSTURE GLOBALE */}
      <section className="posture-card">
        <div className="posture-main">
          <div className="eyebrow">Posture globale de durcissement</div>
          <div className="posture-verdict" style={{ color: p.color }}>
            <svg width="21" height="21" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M12 3l9 16H3l9-16z" stroke="currentColor" strokeWidth="1.9" strokeLinejoin="round" />
              <path d="M12 9v4.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <circle cx="12" cy="16.4" r="1.1" fill="currentColor" />
            </svg>
            {p.label}
            {score != null && <span className="posture-score">{score}<span className="s-max">/100</span></span>}
          </div>
          <div className="posture-bar" role="img" aria-label={`${bon} conformes, ${corriger} à corriger, ${expose} exposés`}>
            <span style={{ flex: bon, background: VERDICT.bon.seg }} />
            <span style={{ flex: corriger, background: VERDICT.corriger.seg }} />
            <span style={{ flex: expose, background: VERDICT.expose.seg }} />
          </div>
        </div>
        <div className="posture-counts">
          <div className="pcount"><span className="n" style={{ color: VERDICT.bon.color }}>{bon}</span><span className="lbl"><i style={{ background: VERDICT.bon.seg }} />conformes</span></div>
          <div className="pcount"><span className="n" style={{ color: VERDICT.corriger.color }}>{corriger}</span><span className="lbl"><i style={{ background: VERDICT.corriger.seg }} />à corriger</span></div>
          <div className="pcount"><span className="n" style={{ color: VERDICT.expose.color }}>{expose}</span><span className="lbl"><i style={{ background: VERDICT.expose.seg }} />exposés</span></div>
        </div>
      </section>

      {/* GROUPES PAR DOMAINE */}
      {groups.map((g, gi) => (
        <section key={gi} className="aud-group">
          <h2 className="aud-gh">{g.title}</h2>
          {g.lines.map((l, li) => {
            const m = VERDICT[l.v] || VERDICT.corriger;
            return (
              <div key={li} className="aud-row">
                <div className="aud-verdict-col">
                  <span className="verdict" style={{ color: m.color, background: m.bg, border: `1px solid ${m.border}` }}>
                    <VerdictIcon v={l.v} />
                    {m.label}
                  </span>
                </div>
                <div className="aud-body">
                  <div className="aud-line-head">
                    <strong>{l.name}</strong>
                    {l.target && <span className="mono aud-target">{l.target}</span>}
                  </div>
                  {(l.detail || l.reco) && (
                    <div className="aud-detail">
                      {l.detail}{l.reco && <span className="aud-reco"> — {l.reco}</span>}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </section>
      ))}

      {groups.length === 0 && (
        <div className="empty">Aucune donnée de durcissement pour cette session.</div>
      )}
    </div>
  );
}
