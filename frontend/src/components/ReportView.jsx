import { useEffect, useState } from "react";
import * as api from "../api/client.js";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = { critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible", info: "Info" };

function sevCounts(findings) {
  const c = {};
  for (const f of findings) {
    const s = SEV_ORDER.includes(f.severity) ? f.severity : "info";
    c[s] = (c[s] || 0) + 1;
  }
  return c;
}
function owaspCovered(findings) {
  const set = new Set();
  for (const f of findings) {
    for (const m of String(f.owasp || "").matchAll(/A\d{2}/g)) set.add(m[0]);
  }
  return [...set].sort();
}

export default function ReportView({ sessionId }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [hasPdf, setHasPdf] = useState(false);
  const [busyPdf, setBusyPdf] = useState(false);
  const [share, setShare] = useState(null);
  const [busyShare, setBusyShare] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true); setError(""); setShare(null);
    api.getReport(sessionId).then((r) => { setReport(r); setHasPdf(!!r.has_pdf); })
      .catch((e) => setError(e.message)).finally(() => setLoading(false));
  }, [sessionId]);

  const genPdf = async () => {
    setBusyPdf(true); setError("");
    try { await api.generatePdf(sessionId); setHasPdf(true); }
    catch (e) { setError(e.message); } finally { setBusyPdf(false); }
  };
  const makeShare = async () => {
    setBusyShare(true); setError("");
    try { const r = await api.createShare(sessionId); setShare({ url: window.location.origin + r.path }); }
    catch (e) { setError(e.message); } finally { setBusyShare(false); }
  };
  const copy = async () => {
    try { await navigator.clipboard.writeText(share.url); setCopied(true); setTimeout(() => setCopied(false), 1600); }
    catch { /* non copiable */ }
  };

  if (loading) return <div className="loading">Chargement du rapport…</div>;
  if (error && !report) return <div className="err">{error}</div>;
  if (!report) return null;

  const s = report.summary || {};
  const findings = s.findings || [];
  const sc = sevCounts(findings);
  const owasp = owaspCovered(findings);
  const today = new Date().toLocaleDateString("fr-FR", { day: "numeric", month: "short", year: "numeric" });

  return (
    <div className="report">
      <div className="rep-head">
        <div className="rep-eyebrow">Rapport de mission</div>
        <div className="rep-title">{s.target || "—"} — test d'intrusion applicatif</div>
        <div className="fc-meta">
          {today}{s.campaign_id && ` · #${String(s.campaign_id).slice(0, 10)}`}
        </div>
      </div>

      <div className="rep-risk">
        <div>
          <div className="rep-eyebrow">Risque global</div>
          <div className={`risk big ${s.overall_risk}`}>{s.overall_risk || "inconnu"}</div>
        </div>
        <div className="rep-actions">
          {!hasPdf ? (
            <button onClick={genPdf} disabled={busyPdf}>{busyPdf ? "Génération…" : "Exporter en PDF"}</button>
          ) : (
            <a className="btn" href={api.downloadUrl(sessionId, "pdf")} download>Télécharger le PDF</a>
          )}
          <button className="offensive" onClick={makeShare} disabled={busyShare}>
            {busyShare ? "Création…" : "Partager un lien"}
          </button>
        </div>
      </div>

      {share && (
        <div className="share-box">
          <div className="fc-meta">Lien public (lecture seule) :</div>
          <div className="share-row">
            <input readOnly value={share.url} onFocus={(e) => e.target.select()} />
            <button onClick={copy}>{copied ? "Copié ✓" : "Copier"}</button>
          </div>
        </div>
      )}
      {error && <div className="err">{error}</div>}

      <div className="rep-stats">
        <div className="stat"><b>{findings.length}</b><span>failles remontées</span></div>
        <div className="stat"><b>{s.proven_count ?? 0}</b><span>prouvées</span></div>
        <div className="stat"><b>{s.detected_count ?? 0}</b><span>détectées</span></div>
        <div className="stat"><b>{owasp.length}/10</b><span>OWASP couvertes</span></div>
      </div>

      <section className="drawer-sec">
        <h4>Répartition par sévérité</h4>
        <div className="sev-dist">
          {SEV_ORDER.filter((x) => sc[x]).map((x) => (
            <span key={x} className="sev-chip">
              <span className={`sev ${x}`}>{SEV_LABEL[x]}</span> {sc[x]}
            </span>
          ))}
          {findings.length === 0 && <span className="fc-meta">Aucune faille.</span>}
        </div>
      </section>

      {owasp.length > 0 && (
        <section className="drawer-sec">
          <h4>Couverture OWASP Top 10</h4>
          <div className="owasp-cov">
            {owasp.map((o) => <span key={o} className="cat">{o}</span>)}
          </div>
        </section>
      )}

      <section className="drawer-sec">
        <h4>Détail des failles</h4>
        <div className="audit-list">
          {findings.map((f, i) => (
            <div key={i} className="audit-item">
              <div className="audit-row">
                <div>
                  <strong>{f.title}</strong>
                  <div className="fc-meta">{f.source}{f.owasp && ` · ${f.owasp}`}{f.cwe && ` · ${f.cwe}`}</div>
                </div>
                <span className={`sev ${SEV_ORDER.includes(f.severity) ? f.severity : "info"}`}>
                  {SEV_LABEL[f.severity] || f.severity}
                </span>
              </div>
            </div>
          ))}
        </div>
      </section>

      <p className="fc-meta rep-foot">
        Document destiné au client · reconductible à l'identique après correction (re-test).
      </p>
    </div>
  );
}
