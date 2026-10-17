import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import * as api from "../api/client.js";
import Brand from "../components/Brand.jsx";

// Nouvelle mission : l'opérateur lance le pentest DE SON site (cible restreinte
// à ses sites autorisés). Formulaire → /api/start → progression live (SSE).
export default function Mission({ user, onLogout }) {
  const navigate = useNavigate();
  const [catalog, setCatalog] = useState(null);
  const [target, setTarget] = useState("");
  const [cats, setCats] = useState([]);
  const [engine, setEngine] = useState("seq");
  const [error, setError] = useState("");
  const [jobId, setJobId] = useState(null);
  const [log, setLog] = useState([]);
  const [status, setStatus] = useState(""); // running | done | error
  const esRef = useRef(null);
  const logEndRef = useRef(null);

  useEffect(() => {
    api
      .getCatalog()
      .then((c) => {
        setCatalog(c);
        if (c.targets?.length) setTarget(c.targets[0]);
        setCats((c.categories || []).map((x) => x.id)); // tout coché par défaut
        if (c.engines?.length) setEngine(c.engines.includes("seq") ? "seq" : c.engines[0]);
      })
      .catch((e) => setError(e.message));
    return () => esRef.current?.close();
  }, []);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [log]);

  const toggleCat = (id) =>
    setCats((cs) => (cs.includes(id) ? cs.filter((c) => c !== id) : [...cs, id]));

  const launch = async () => {
    setError("");
    setLog([]);
    setStatus("running");
    try {
      const r = await api.startCampaign({
        target,
        actions: cats,
        operator: user.operator,
        engine,
      });
      setJobId(r.job_id);
      // Ouvre le flux SSE de progression.
      const es = new EventSource(api.streamUrl(r.job_id));
      esRef.current = es;
      es.onmessage = (ev) => {
        try {
          const d = JSON.parse(ev.data);
          if (d.line) setLog((l) => [...l, d.line]);
          if (d.status) {
            setStatus(d.status);
            es.close();
          }
        } catch {
          /* commentaire keepalive */
        }
      };
      es.onerror = () => {
        es.close();
        setStatus((s) => (s === "running" ? "error" : s));
      };
    } catch (e) {
      setStatus("");
      setError(e.message);
    }
  };

  const noTargets = catalog && (catalog.targets || []).length === 0;
  const running = status === "running";

  return (
    <div className="shell">
      <header className="topbar">
        <Brand />
        <div className="who">
          <button onClick={() => navigate("/")}>← Console</button>
          <span>
            {user.operator} ({user.role})
          </span>
          <button
            onClick={async () => {
              try { await api.logout(); } finally { await onLogout(); }
            }}
          >
            Déconnexion
          </button>
        </div>
      </header>

      <div className="admin-wrap">
        <h1 className="admin-h1">Nouvelle mission</h1>
        <p className="fc-meta">
          Lancez une campagne de test d'intrusion sur un de vos sites autorisés.
          Gouvernance RoE appliquée (deny-by-default).
        </p>

        {error && <div className="err">{error}</div>}

        {noTargets ? (
          <div className="empty">
            Aucun site ne vous est autorisé. Demandez à un administrateur de vous
            attribuer un site dans l'espace d'administration.
          </div>
        ) : catalog ? (
          <div className="mission-form">
            <div className="field">
              <label>Site cible</label>
              <select value={target} onChange={(e) => setTarget(e.target.value)} disabled={running}>
                {catalog.targets.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>

            <div className="field">
              <label>Catégories autorisées (RoE)</label>
              {catalog.categories.length === 0 && (
                <div className="fc-meta">
                  Aucune catégorie autorisée par l'administrateur pour cette politique.
                </div>
              )}
              <div className="site-checks">
                {catalog.categories.map((c) => (
                  <label key={c.id} className="site-check">
                    <input
                      type="checkbox"
                      checked={cats.includes(c.id)}
                      disabled={running}
                      onChange={() => toggleCat(c.id)}
                    />
                    <span>{c.label}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="field">
              <label>Moteur d'orchestration</label>
              <select value={engine} onChange={(e) => setEngine(e.target.value)} disabled={running}>
                {catalog.engines.map((e2) => (
                  <option key={e2} value={e2}>{e2 === "seq" ? "Séquentiel" : e2}</option>
                ))}
              </select>
            </div>

            <button
              className="primary"
              onClick={launch}
              disabled={running || !target || cats.length === 0}
            >
              {running ? "Campagne en cours…" : "Lancer la campagne"}
            </button>
          </div>
        ) : (
          <div className="loading">Chargement…</div>
        )}

        {(log.length > 0 || status) && (
          <div className="mission-progress">
            <div className="pane-head">
              Progression {status && `· ${status}`}
            </div>
            <pre className="mission-log">
              {log.join("\n")}
              <span ref={logEndRef} />
            </pre>
            {status === "done" && (
              <button
                className="primary"
                onClick={() => navigate("/", { state: { sessionId: jobId, tab: "findings" } })}
              >
                Voir les résultats
              </button>
            )}
            {status === "error" && (
              <div className="err">La campagne a échoué. Consultez le journal ci-dessus.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
