import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import * as api from "../api/client.js";
import TopNav from "../components/TopNav.jsx";

// Descriptions RoE (fidèles à la maquette), par catégorie.
const ROE_DESC = {
  passive: "OSINT, empreinte publique, DNS, sous-domaines. Aucune sollicitation intrusive de la cible.",
  active_scan: "Sondes réseau et web non destructives, détection et démonstration automatique des failles (état « Prouvé »).",
  exploitation: "Confirmation d'impact à la demande de l'opérateur (/exploit), toujours bornée à la preuve, sans exfiltration ni écriture destructive.",
};
const ENGINE_DESC = {
  seq: { name: "Séquentiel", tag: "· défaut", desc: "Phases l'une après l'autre. Lisible, prévisible." },
  langgraph: { name: "Graphe parallèle", tag: "", desc: "Branches concurrentes (LangGraph). Plus rapide sur large surface." },
};

export default function Mission({ user, onLogout }) {
  const navigate = useNavigate();
  const [catalog, setCatalog] = useState(null);
  const [target, setTarget] = useState("");
  const [cats, setCats] = useState([]);
  const [engine, setEngine] = useState("seq");
  const [error, setError] = useState("");
  const [jobId, setJobId] = useState(null);
  const [log, setLog] = useState([]);
  const [status, setStatus] = useState("");
  const esRef = useRef(null);
  const logEndRef = useRef(null);

  useEffect(() => {
    api.getCatalog().then((c) => {
      setCatalog(c);
      if (c.targets?.length) setTarget(c.targets[0]);
      setCats((c.categories || []).map((x) => x.id));
      if (c.engines?.length) setEngine(c.engines.includes("seq") ? "seq" : c.engines[0]);
    }).catch((e) => setError(e.message));
    return () => esRef.current?.close();
  }, []);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [log]);

  const toggleCat = (id) =>
    setCats((cs) => (cs.includes(id) ? cs.filter((c) => c !== id) : [...cs, id]));

  const launch = async () => {
    setError(""); setLog([]); setStatus("running");
    try {
      const r = await api.startCampaign({ target, actions: cats, operator: user.operator, engine });
      setJobId(r.job_id);
      const es = new EventSource(api.streamUrl(r.job_id));
      esRef.current = es;
      es.onmessage = (ev) => {
        try {
          const d = JSON.parse(ev.data);
          if (d.line) setLog((l) => [...l, d.line]);
          if (d.status) { setStatus(d.status); es.close(); }
        } catch { /* keepalive */ }
      };
      es.onerror = () => { es.close(); setStatus((s) => (s === "running" ? "error" : s)); };
    } catch (e) { setStatus(""); setError(e.message); }
  };

  const noTargets = catalog && (catalog.targets || []).length === 0;
  const running = status === "running";

  return (
    <div className="page">
      <TopNav active="missions" user={user} onLogout={onLogout} />

      <main className="page-main">
        <div className="page-wrap">
          <div className="crumb">Missions / nouvelle</div>
          <h1 className="page-title">Nouvelle mission</h1>
          <p className="page-lede">
            Une mission = une cible + un périmètre d'actions autorisées. Rien n'est
            permis qui n'ait été coché — le périmètre est fermé par défaut.
          </p>

          {error && <div className="err">{error}</div>}

          {noTargets ? (
            <div className="empty">
              Aucun site ne vous est autorisé. Demandez à un administrateur de vous
              attribuer un site dans l'espace d'administration.
            </div>
          ) : catalog ? (
            <div className="mform">
              {/* 1 · Cible */}
              <section className="fcard">
                <div className="fcard-h"><span className="step-n">1</span><h2>Cible</h2></div>
                <label className="fld-label">URL ou domaine à tester</label>
                <div className="fld mono">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8" />
                    <path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" stroke="currentColor" strokeWidth="1.6" />
                  </svg>
                  <select value={target} onChange={(e) => setTarget(e.target.value)} disabled={running}>
                    {catalog.targets.map((t) => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
              </section>

              {/* 2 · RoE */}
              <section className="fcard">
                <div className="fcard-h">
                  <span className="step-n">2</span><h2>Périmètre autorisé · RoE</h2>
                  <span className="roe-pill">🔒 fermé par défaut</span>
                </div>
                <p className="fcard-sub">
                  Chaque catégorie décochée sera refusée par le garde-fou, même si
                  l'agent la juge utile.
                </p>
                <div className="roe-list">
                  {catalog.categories.length === 0 && (
                    <div className="fc-meta">Aucune catégorie autorisée par l'administrateur.</div>
                  )}
                  {catalog.categories.map((c) => {
                    const on = cats.includes(c.id);
                    const exploit = c.id === "exploitation";
                    return (
                      <label key={c.id} className={`roe-opt ${on ? "on" : ""} ${exploit ? "dashed" : ""}`}>
                        <input type="checkbox" checked={on} disabled={running} onChange={() => toggleCat(c.id)} />
                        <span className="roe-body">
                          <span className="roe-title">
                            <strong>{c.label}</strong>
                            <span className={`roe-badge ${on ? "ok" : "no"}`}>{on ? "autorisé" : "refusé"}</span>
                          </span>
                          <span className="roe-desc">{ROE_DESC[c.id] || ""}</span>
                        </span>
                      </label>
                    );
                  })}
                </div>
              </section>

              {/* 3 · Moteur */}
              <section className="fcard">
                <div className="fcard-h"><span className="step-n">3</span><h2>Moteur d'orchestration</h2></div>
                <div className="engine-row">
                  {catalog.engines.map((e2) => {
                    const info = ENGINE_DESC[e2] || { name: e2, tag: "", desc: "" };
                    return (
                      <label key={e2} className={`engine-opt ${engine === e2 ? "on" : ""}`}>
                        <input type="radio" name="engine" checked={engine === e2}
                          disabled={running} onChange={() => setEngine(e2)} />
                        <span>
                          <strong>{info.name}</strong> <span className="fc-meta">{info.tag}</span>
                          <span className="engine-desc">{info.desc}</span>
                        </span>
                      </label>
                    );
                  })}
                </div>
              </section>

              {/* Rappel légal */}
              <div className="legal">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M12 3l9 16H3l9-16z" stroke="currentColor" strokeWidth="1.9" strokeLinejoin="round" />
                  <path d="M12 10v4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                  <circle cx="12" cy="16.6" r="1.1" fill="currentColor" />
                </svg>
                <p>
                  <strong>Rappel légal.</strong> Cocher une catégorie donne l'accord
                  <em> technique</em> à l'agent ; cela n'emporte pas l'autorisation
                  <em> légale</em> de tester cette cible. Assurez-vous d'y être habilité.
                </p>
              </div>

              {/* Actions */}
              <div className="mform-actions">
                <button className="link" onClick={() => navigate("/")} disabled={running}>Annuler</button>
                <button className="primary" onClick={launch} disabled={running || !target || cats.length === 0}>
                  {running ? "Campagne en cours…" : "Créer la mission →"}
                </button>
              </div>
            </div>
          ) : (
            <div className="loading">Chargement…</div>
          )}

          {(log.length > 0 || status) && (
            <div className="mission-progress">
              <div className="pane-head">Progression {status && `· ${status}`}</div>
              <pre className="mission-log">{log.join("\n")}<span ref={logEndRef} /></pre>
              {status === "done" && (
                <button className="primary" onClick={() => navigate("/", { state: { sessionId: jobId, tab: "findings" } })}>
                  Voir les résultats
                </button>
              )}
              {status === "error" && (
                <div className="err">La campagne a échoué. Consultez le journal ci-dessus.</div>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
