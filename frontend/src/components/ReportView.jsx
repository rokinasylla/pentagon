import { useEffect, useState } from "react";
import * as api from "../api/client.js";

const SEV = ["critical", "high", "medium", "low", "info"];
const sevClass = (s) => (SEV.includes(s) ? s : "info");

export default function ReportView({ sessionId }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [busyPdf, setBusyPdf] = useState(false);
  const [hasPdf, setHasPdf] = useState(false);
  const [share, setShare] = useState(null); // {url}
  const [busyShare, setBusyShare] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true);
    setError("");
    setShare(null);
    api
      .getReport(sessionId)
      .then((r) => {
        setReport(r);
        setHasPdf(!!r.has_pdf);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [sessionId]);

  const genPdf = async () => {
    setBusyPdf(true);
    setError("");
    try {
      await api.generatePdf(sessionId);
      setHasPdf(true);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyPdf(false);
    }
  };

  const makeShare = async () => {
    setBusyShare(true);
    setError("");
    try {
      const r = await api.createShare(sessionId);
      setShare({ url: window.location.origin + r.path });
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyShare(false);
    }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(share.url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* copie indisponible : l'URL reste sélectionnable */
    }
  };

  if (loading) return <div className="loading">Chargement du rapport…</div>;
  if (error && !report) return <div className="err">{error}</div>;
  if (!report) return null;

  const s = report.summary || {};
  const findings = s.findings || [];

  return (
    <div className="report">
      <div className="report-head">
        <div>
          <div className="audit-title">Rapport de campagne</div>
          <div className="fc-meta">
            {s.target || "—"} · risque global <strong>{s.overall_risk || "inconnu"}</strong>
          </div>
        </div>
      </div>

      <div className="cards">
        <div className="card">
          <div className="card-n">{s.proven_count ?? 0}</div>
          <div className="fc-meta">Prouvées</div>
        </div>
        <div className="card">
          <div className="card-n">{s.detected_count ?? 0}</div>
          <div className="fc-meta">Détectées</div>
        </div>
      </div>

      <div className="report-actions">
        {!hasPdf && (
          <button onClick={genPdf} disabled={busyPdf}>
            {busyPdf ? "Génération…" : "Générer le PDF"}
          </button>
        )}
        {hasPdf && (
          <a className="btn" href={api.downloadUrl(sessionId, "pdf")} download>
            Télécharger le PDF
          </a>
        )}
        {report.has_json && (
          <a className="btn" href={api.downloadUrl(sessionId, "json")} download>
            Télécharger le JSON
          </a>
        )}
        <button className="offensive" onClick={makeShare} disabled={busyShare}>
          {busyShare ? "Création…" : "Créer un lien de partage"}
        </button>
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

      <section className="audit-sec">
        <h4>Vulnérabilités ({findings.length})</h4>
        <div className="audit-list">
          {findings.length === 0 && <p className="audit-empty">Aucune vulnérabilité.</p>}
          {findings.map((f, i) => (
            <div key={i} className="audit-item">
              <div className="audit-row">
                <div>
                  <strong>{f.title}</strong>
                  <div className="fc-meta">
                    {f.source} {f.owasp && `· ${f.owasp}`} {f.cwe && `· ${f.cwe}`}
                  </div>
                </div>
                <span className={`sev ${sevClass(f.severity)}`}>{f.severity}</span>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
