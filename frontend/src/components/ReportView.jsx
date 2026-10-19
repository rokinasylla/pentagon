import { useEffect, useState } from "react";
import * as api from "../api/client.js";
import ReportPanel, { sevSeries, owaspCoverage } from "./ReportPanel.jsx";

// proof_state (ou state) d'une faille -> clé d'état attendue par ReportPanel.
function findingState(f) {
  const s = String(f.proof_state || f.state || "").toLowerCase();
  if (s.includes("confirm")) return "confirmed";
  if (s.includes("prouv") || s.includes("proven")) return "proven";
  return "detected";
}

function toFindings(raw) {
  return raw.map((f) => ({
    severity: f.severity,
    title: f.title,
    cat: [f.owasp, f.cwe].filter(Boolean).join(" · ") || f.source || "",
    state: findingState(f),
  }));
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
  const rawFindings = s.findings || [];
  const findings = toFindings(rawFindings);
  const owasp = owaspCoverage(rawFindings);
  const confirmed = s.confirmed_count ?? findings.filter((f) => f.state === "confirmed").length;
  const today = new Date().toLocaleDateString("fr-FR", { day: "numeric", month: "short", year: "numeric" });

  const meta = {
    target: s.target,
    operator: s.operator || report.operator,
    date: today,
    campaignId: s.campaign_id ? String(s.campaign_id).slice(0, 10) : null,
    risk: s.overall_risk,
  };
  const stats = {
    total: rawFindings.length,
    proven: s.proven_count ?? 0,
    confirmed,
    owaspCovered: owasp.filter((o) => o.state === "t").length,
  };

  const actions = (
    <>
      {!hasPdf ? (
        <button className="rep-btn primary" onClick={genPdf} disabled={busyPdf}>
          {busyPdf ? "Génération…" : "Exporter en PDF"}
        </button>
      ) : (
        <a className="rep-btn primary" href={api.downloadUrl(sessionId, "pdf")} download>Télécharger le PDF</a>
      )}
      <button className="rep-btn" onClick={makeShare} disabled={busyShare}>
        {busyShare ? "Création…" : "Partager un lien"}
      </button>
    </>
  );

  return (
    <>
      <ReportPanel
        meta={meta}
        stats={stats}
        sev={sevSeries(rawFindings)}
        owasp={owasp}
        findings={findings}
        actions={actions}
      />
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
    </>
  );
}
