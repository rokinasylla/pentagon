import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import * as api from "../api/client.js";
import TopNav from "../components/TopNav.jsx";

const ROE_DESC = {
  passive: "OSINT, empreinte publique, DNS, sous-domaines. Aucune sollicitation intrusive de la cible.",
  active_scan: "Sondes réseau et web non destructives, détection et démonstration automatique des failles (état « Prouvé »).",
  exploitation: "Confirmation d'impact à la demande de l'opérateur (/exploit), toujours bornée à la preuve, sans exfiltration ni écriture destructive.",
};
const ENGINE_DESC = {
  seq: { name: "Séquentiel", tag: "· défaut", desc: "Phases l'une après l'autre. Lisible, prévisible." },
  langgraph: { name: "Graphe parallèle", tag: "", desc: "Branches concurrentes (LangGraph). Plus rapide sur large surface." },
};
// Phases du pentest (annoncées par l'orchestrateur : « PHASE N — … »).
const PHASES = [
  { n: 1, label: "Reconnaissance (OSINT)" },
  { n: 2, label: "Scan réseau" },
  { n: 3, label: "Application web" },
  { n: 4, label: "Exploitation" },
];
const STORE_KEY = "pentagon_running_job";

export default function Mission({ user, onLogout }) {
  const navigate = useNavigate();
  const [catalog, setCatalog] = useState(null);
  const [target, setTarget] = useState("");
  const [cats, setCats] = useState([]);
  const [engine, setEngine] = useState("seq");
  const [error, setError] = useState("");
  const [jobId, setJobId] = useState(null);
  const [log, setLog] = useState([]);
  const [status, setStatus] = useState(""); // "" | running | done | error
  const [phase, setPhase] = useState(0);
  const esRef = useRef(null);
  const logEndRef = useRef(null);

  // Ouvre (ou ré-ouvre) le flux SSE d'une campagne et suit sa progression.
  const attach = (id) => {
    esRef.current?.close();
    setJobId(id);
    setStatus("running");
    setLog([]);
    setPhase(0);
    try { localStorage.setItem(STORE_KEY, id); } catch { /* ignore */ }
    const es = new EventSource(api.streamUrl(id));
    esRef.current = es;
    es.onmessage = (ev) => {
      try {
        const d = JSON.parse(ev.data);
        if (d.line) {
          setLog((l) => [...l, d.line]);
          const m = /PHASE\s+(\d)/.exec(d.line);
          if (m) setPhase(Math.max(Number(m[1]), 0));
        }
        if (d.status) {
          setStatus(d.status);
          if (d.status === "done") setPhase(PHASES.length);
          es.close();
          try { localStorage.removeItem(STORE_KEY); } catch { /* ignore */ }
        }
      } catch { /* keepalive */ }
    };
    es.onerror = () => {
      es.close();
      setStatus((s) => (s === "running" ? "error" : s));
    };
  };

  useEffect(() => {
    api.getCatalog().then((c) => {
      setCatalog(c);
      setCats((c.categories || []).map((x) => x.id));
      if (c.engines?.length) setEngine(c.engines.includes("seq") ? "seq" : c.engines[0]);
    }).catch((e) => setError(e.message));

    // RECONNEXION : si une campagne tourne déjà (mémorisée, ou détectée côté
    // serveur), on s'y ré-attache — elle ne s'arrête pas quand on change d'onglet.
    (async () => {
      let id = null;
      try { id = localStorage.getItem(STORE_KEY); } catch { /* ignore */ }
      if (!id) {
        try {
          const d = await api.listSessions();
          const running = (d.jobs || []).find((j) => j.status === "running");
          if (running) id = running.job_id;
        } catch { /* ignore */ }
      }
      if (id) attach(id);
    })();

    return () => esRef.current?.close();
  }, []);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [log]);

  const toggleCat = (id) =>
    setCats((cs) => (cs.includes(id) ? cs.filter((c) => c !== id) : [...cs, id]));

  const launch = async () => {
    setError("");
    try {
      const r = await api.startCampaign({ target, actions: cats, operator: user.operator, engine });
      attach(r.job_id);
    } catch (e) {
      setStatus("");
      setError(e.status === 403
        ? `⛔ Le site « ${target} » n'est pas autorisé. Demandez à un administrateur de l'ajouter aux sites autorisés.`
        : e.message);
    }
  };

  const running = status === "running";
  const done = status === "done";
  const curPhase = PHASES.find((p) => p.n === phase);

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

          {/* ─── Suivi de campagne (si en cours / terminée) ─── */}
          {(running || done || status === "error") && (
            <div className={`campaign ${status}`}>
              <div className="camp-head">
                <div className="camp-state">
                  {running && <span className="spinner" aria-hidden="true" />}
                  {running && <>Pentest en cours{curPhase ? ` · ${curPhase.label}` : "…"}</>}
                  {done && <>✓ Pentest terminé</>}
                  {status === "error" && <>✗ Échec du pentest</>}
                </div>
                {done && (
                  <button className="primary sm" onClick={() => navigate("/", { state: { sessionId: jobId, tab: "findings" } })}>
                    Voir les résultats →
                  </button>
                )}
              </div>

              {/* Stepper des phases */}
              <ol className="stepper">
                {PHASES.map((p) => {
                  const state = done ? "done"
                    : p.n < phase ? "done"
                    : p.n === phase ? "cur"
                    : "todo";
                  return (
                    <li key={p.n} className={`step ${state}`}>
                      <span className="step-dot">{state === "done" ? "✓" : p.n}</span>
                      <span className="step-label">{p.label}</span>
                    </li>
                  );
                })}
              </ol>

              <details className="camp-log">
                <summary>Journal détaillé</summary>
                <pre className="mission-log">{log.join("\n")}<span ref={logEndRef} /></pre>
              </details>
              {running && (
                <p className="fc-meta">
                  Vous pouvez quitter cet onglet : la campagne continue côté serveur,
                  et ce suivi se reconnecte quand vous revenez.
                </p>
              )}
            </div>
          )}

          {catalog && !running && !done && (
            <div className="mform">
              {/* 1 · Cible (saisie libre) */}
              <section className="fcard">
                <div className="fcard-h"><span className="step-n">1</span><h2>Cible</h2></div>
                <label className="fld-label" htmlFor="mtarget">URL ou domaine à tester</label>
                <div className="fld mono">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8" />
                    <path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" stroke="currentColor" strokeWidth="1.6" />
                  </svg>
                  <input id="mtarget" list="site-suggest" value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="exemple.com" autoComplete="off" />
                  <datalist id="site-suggest">
                    {(catalog.suggestions || []).map((t) => <option key={t} value={t} />)}
                  </datalist>
                </div>
                <p className="fc-meta" style={{ marginTop: 8 }}>
                  Saisissez n'importe quel site. Si le site n'est pas autorisé, la
                  campagne sera bloquée — demandez son autorisation à l'administrateur.
                </p>
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
                        <input type="checkbox" checked={on} onChange={() => toggleCat(c.id)} />
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
                        <input type="radio" name="engine" checked={engine === e2} onChange={() => setEngine(e2)} />
                        <span>
                          <strong>{info.name}</strong> <span className="fc-meta">{info.tag}</span>
                          <span className="engine-desc">{info.desc}</span>
                        </span>
                      </label>
                    );
                  })}
                </div>
              </section>

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

              <div className="mform-actions">
                <button className="link" onClick={() => navigate("/")}>Annuler</button>
                <button className="primary" onClick={launch} disabled={!target || cats.length === 0}>
                  Créer la mission →
                </button>
              </div>
            </div>
          )}

          {/* Relancer après une campagne terminée */}
          {(done || status === "error") && (
            <div className="mform-actions" style={{ marginTop: 18 }}>
              <button onClick={() => { setStatus(""); setPhase(0); setLog([]); setJobId(null); }}>
                Lancer une autre mission
              </button>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
