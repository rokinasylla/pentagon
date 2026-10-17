import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import * as api from "../api/client.js";
import TopNav from "../components/TopNav.jsx";

// Vue d'ensemble MULTI-CAS (pages d'index Audits / Rapports) : une ligne par
// campagne. Un clic ouvre la console sur la session et l'onglet correspondant.
function scoreCls(score) {
  if (score == null) return "info";
  if (score >= 80) return "low";
  if (score >= 50) return "medium";
  if (score >= 25) return "high";
  return "critical";
}

export default function Overview({ user, onLogout }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [view, setView] = useState(location.state?.view === "reports" ? "reports" : "audits");
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .getIndex()
      .then((d) => setRows(d.sessions || []))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const open = (jobId, tab) =>
    navigate("/", { state: { sessionId: jobId, tab } });

  const doLogout = async () => {
    try {
      await api.logout();
    } finally {
      await onLogout();
    }
  };

  return (
    <div className="page">
      <TopNav active={view === "reports" ? "rapports" : "audits"} user={user} onLogout={onLogout} />

      <main className="page-main">
        <div className="page-wrap">
          <h1 className="page-title">Vue d'ensemble</h1>
        <div className="seg">
          <button
            className={view === "audits" ? "on" : ""}
            onClick={() => setView("audits")}
          >
            Audits
          </button>
          <button
            className={view === "reports" ? "on" : ""}
            onClick={() => setView("reports")}
          >
            Rapports
          </button>
        </div>

        {error && <div className="err">{error}</div>}
        {loading && <div className="loading">Chargement…</div>}
        {!loading && rows.length === 0 && (
          <div className="empty">Aucune campagne enregistrée.</div>
        )}

        {!loading && rows.length > 0 && (
          <div className="idx-table">
            <div className="idx-head">
              <span>Cible</span>
              <span>Date</span>
              {view === "audits" ? <span>Durcissement</span> : <span>Findings</span>}
              <span>Risque</span>
              <span></span>
            </div>
            {rows.map((r) => (
              <div key={r.job_id} className="idx-row">
                <span className="idx-target">{r.target || r.job_id}</span>
                <span className="fc-meta">{(r.started_at || "").slice(0, 10)}</span>
                {view === "audits" ? (
                  <span>
                    <span className={`score-pill ${scoreCls(r.security_score)}`}>
                      {r.security_score ?? "—"}/100
                    </span>
                  </span>
                ) : (
                  <span className="fc-meta">
                    {r.proven_count}P / {r.detected_count}D{" "}
                    {r.has_pdf && <span className="cat">PDF</span>}
                  </span>
                )}
                <span className={`risk ${r.overall_risk}`}>{r.overall_risk}</span>
                <span>
                  <button
                    className="link"
                    onClick={() => open(r.job_id, view === "audits" ? "audit" : "report")}
                  >
                    Ouvrir
                  </button>
                </span>
              </div>
            ))}
          </div>
        )}
        </div>
      </main>
    </div>
  );
}
