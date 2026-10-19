// Panneau présentationnel de l'onglet Rapport (fidèle à Rapport.dc.html).
// Pur : aucune logique réseau. Les actions (PDF / partage), qui dépendent de
// l'API, sont injectées par le conteneur via la prop `actions`.

const SEV = {
  critical: { label: "Critique", color: "#6E1F2E" },
  high: { label: "Élevée", color: "#B0541E" },
  medium: { label: "Moyenne", color: "#8A6A12" },
  low: { label: "Faible", color: "#3C6686" },
  info: { label: "Info", color: "#6B6F79" },
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

// Top 10 OWASP 2021 (libellés FR), ordre fixe.
const OWASP10 = [
  ["A01", "Contrôle d’accès"], ["A02", "Défaillances crypto"],
  ["A03", "Injection"], ["A04", "Conception non sûre"],
  ["A05", "Mauvaise config."], ["A06", "Composants vulnérables"],
  ["A07", "Auth. défaillante"], ["A08", "Intégrité logicielle"],
  ["A09", "Journalisation"], ["A10", "SSRF"],
];
const OW_COLOR = { t: "#6E1F2E", c: "#3C6686", n: "#6B6F79" };

const STATE = {
  confirmed: { label: "Confirmé", color: "#FFFFFF", bg: "#B0541E", border: "#B0541E" },
  proven: { label: "Prouvé", color: "#2E3A59", bg: "#EDEFF4", border: "#D7DCEA" },
  detected: { label: "Détecté", color: "#6B6F79", bg: "#F4F3EE", border: "#DEDBD2" },
};

function riskColor(risk) {
  const r = String(risk || "").toLowerCase();
  if (r.includes("crit")) return "#6E1F2E";
  if (r.includes("élev") || r.includes("elev") || r === "high") return "#6E1F2E";
  if (r.includes("moy") || r === "medium") return "#8A6A12";
  if (r.includes("faible") || r === "low") return "#3C6686";
  return "#6B6F79";
}

function OwaspIcon({ state }) {
  if (state === "c") {
    return (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  if (state === "n") {
    return (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8" strokeDasharray="2 3" />
      </svg>
    );
  }
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2" />
      <path d="M12 7v5" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
      <circle cx="12" cy="16" r="1.1" fill="currentColor" />
    </svg>
  );
}

export default function ReportPanel({ meta = {}, stats = {}, sev = [], owasp = [], findings = [], actions = null }) {
  const sevMax = Math.max(1, ...sev.map((s) => s.n || 0));
  const rc = riskColor(meta.risk);

  return (
    <div className="report-panel">
      {/* EN-TÊTE */}
      <section className="rep-header">
        <div className="rep-head-main">
          <div className="eyebrow">Rapport de mission</div>
          <h1 className="rep-title">{meta.target || "—"} — test d’intrusion applicatif</h1>
          <div className="rep-meta mono">
            {[meta.operator, meta.date, meta.campaignId && `#${meta.campaignId}`].filter(Boolean).join(" · ")}
          </div>
        </div>
        <div className="rep-risk">
          <div className="eyebrow">Risque global</div>
          <span className="rep-risk-val" style={{ color: rc }}>
            <span className="swatch" style={{ background: rc }} />{meta.risk || "inconnu"}
          </span>
        </div>
      </section>

      {actions && <div className="rep-actions">{actions}</div>}

      {/* STATS */}
      <div className="rep-stats">
        <div className="stat"><b>{stats.total ?? 0}</b><span>failles remontées</span></div>
        <div className="stat"><b style={{ color: "#2E3A59" }}>{stats.proven ?? 0}</b><span>prouvées</span></div>
        <div className="stat"><b style={{ color: "#B0541E" }}>{stats.confirmed ?? 0}</b><span>confirmées</span></div>
        <div className="stat"><b>{stats.owaspCovered ?? 0}<span className="s-max">/10</span></b><span>OWASP couvertes</span></div>
      </div>

      {/* SÉVÉRITÉ + OWASP */}
      <div className="rep-cols">
        <section className="rep-card">
          <h2>Répartition par sévérité</h2>
          <div className="sevbars">
            {sev.map((s) => (
              <div key={s.key} className="sevbar">
                <span className="sevbar-label" style={{ color: s.color }}>
                  <i className="swatch" style={{ background: s.color }} />{s.label}
                </span>
                <span className="sevbar-track">
                  <span className="sevbar-fill" style={{ width: `${((s.n || 0) / sevMax) * 100}%`, background: s.color }} />
                </span>
                <span className="sevbar-n mono">{s.n || 0}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="rep-card">
          <h2>Couverture OWASP Top 10</h2>
          <div className="owasp10">
            {owasp.map((o) => (
              <div key={o.id} className="ow-item">
                <span className="ow-icon" style={{ color: OW_COLOR[o.state] }}><OwaspIcon state={o.state} /></span>
                <span className="ow-id mono">{o.id}</span>
                <span className="ow-name">{o.name}</span>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* DÉTAIL DES FAILLES */}
      <section className="rep-detail">
        <h2>Détail des failles</h2>
        {findings.map((f, i) => {
          const sv = SEV[f.severity] || SEV.info;
          const st = STATE[f.state] || STATE.detected;
          return (
            <div key={i} className="rd-row">
              <span className="rd-sev" style={{ color: sv.color }}>
                <i className="swatch" style={{ background: sv.color }} />{sv.label}
              </span>
              <span className="rd-title">{f.title}</span>
              <span className="rd-cat mono">{f.cat}</span>
              <span className="rd-state" style={{ color: st.color, background: st.bg, border: `1px solid ${st.border}` }}>
                {st.label}
              </span>
            </div>
          );
        })}
        {findings.length === 0 && <div className="fc-meta">Aucune faille.</div>}
      </section>

      <p className="rep-foot">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 3l7 3v5c0 4.2-2.8 7.6-7 9-4.2-1.4-7-4.8-7-9V6l7-3z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
        </svg>
        Document destiné au client · reconductible à l’identique après correction (re-test).
      </p>
    </div>
  );
}

// Helpers de normalisation réutilisés par le conteneur et l'aperçu.
export function sevSeries(findings) {
  const c = {};
  for (const f of findings) {
    const s = SEV_ORDER.includes(f.severity) ? f.severity : "info";
    c[s] = (c[s] || 0) + 1;
  }
  return SEV_ORDER.map((k) => ({ key: k, label: SEV[k].label, color: SEV[k].color, n: c[k] || 0 }));
}

export function owaspCoverage(findings) {
  const touched = new Set();
  for (const f of findings) {
    for (const m of String(f.owasp || "").matchAll(/A\d{2}/g)) touched.add(m[0]);
  }
  return OWASP10.map(([id, name]) => ({ id, name, state: touched.has(id) ? "t" : "n" }));
}
