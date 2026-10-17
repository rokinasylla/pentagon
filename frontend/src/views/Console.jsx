import { useEffect, useState } from "react";
import * as api from "../api/client.js";
import Brand from "../components/Brand.jsx";
import FindingCard from "../components/FindingCard.jsx";

// Pré-prompts : amorces orientées cyber pour un propriétaire de site non expert.
const PREPROMPTS = [
  "Quelles failles sont prouvées sur mon site ?",
  "Explique-moi la plus grave simplement",
  "Comment corriger la vulnérabilité n°1 ?",
];

export default function Console({ user, onLogout }) {
  const [sessions, setSessions] = useState([]);
  const [activeId, setActiveId] = useState("");
  const [findings, setFindings] = useState([]);
  const [loadingF, setLoadingF] = useState(false);
  const [error, setError] = useState("");

  // Charge l'inventaire des campagnes au montage.
  useEffect(() => {
    (async () => {
      try {
        const data = await api.listSessions();
        const jobs = data.jobs || [];
        setSessions(jobs);
        const firstDone = jobs.find((j) => j.has_summary) || jobs[0];
        if (firstDone) setActiveId(firstDone.job_id);
      } catch (err) {
        setError(err.message);
      }
    })();
  }, []);

  // Charge les findings de la session active.
  useEffect(() => {
    if (!activeId) {
      setFindings([]);
      return;
    }
    setLoadingF(true);
    setError("");
    api
      .getFindings(activeId)
      .then((data) => setFindings(data.findings || []))
      .catch((err) => setError(err.message))
      .finally(() => setLoadingF(false));
  }, [activeId]);

  const doLogout = async () => {
    try {
      await api.logout();
    } finally {
      await onLogout();
    }
  };

  return (
    <div className="shell">
      <header className="topbar">
        <Brand />
        <div className="session-pick">
          <label htmlFor="sess" style={{ color: "var(--fg-faint)", fontSize: 12 }}>
            Session
          </label>
          <select
            id="sess"
            value={activeId}
            onChange={(e) => setActiveId(e.target.value)}
          >
            {sessions.length === 0 && <option value="">Aucune campagne</option>}
            {sessions.map((s) => (
              <option key={s.job_id} value={s.job_id}>
                {s.target || s.job_id} — {s.overall_risk}
              </option>
            ))}
          </select>
        </div>
        <div className="who">
          <span>
            {user.operator} ({user.role})
          </span>
          <button onClick={doLogout}>Déconnexion</button>
        </div>
      </header>

      <div className="panes">
        {/* ─── FIL (conversation) ─── */}
        <section className="pane fil">
          <div className="pane-head">Fil</div>
          <div className="pane-body">
            <div className="msg">
              <div className="role">Assistant</div>
              <div className="body">
                Bienvenue dans la console PENTAGON. Choisissez une session, puis
                posez une question ou lancez une commande.
              </div>
            </div>
            <div className="preprompts">
              {PREPROMPTS.map((p) => (
                <button key={p} className="chip" type="button" disabled title="Branché au Lot UI-2">
                  {p}
                </button>
              ))}
            </div>
          </div>
          <div className="cmdbar" style={{ flexDirection: "column", alignItems: "stretch" }}>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                placeholder="/exploit 1 · ou écrivez en langage naturel…"
                disabled
                aria-label="Barre de commande (Lot UI-2)"
              />
              <button className="primary" disabled>
                Envoyer
              </button>
            </div>
            <div className="note">
              La barre de commandes et l'exploitation à la demande arrivent au Lot UI-2.
            </div>
          </div>
        </section>

        {/* ─── CANEVAS (findings) ─── */}
        <section className="pane canevas">
          <div className="pane-head">
            Findings {findings.length > 0 && `(${findings.length})`}
          </div>
          <div className="pane-body">
            {error && <div className="err">{error}</div>}
            {loadingF && <div className="loading">Chargement des findings…</div>}
            {!loadingF && !error && findings.length === 0 && (
              <div className="empty">
                Aucune faille à afficher pour cette session.
              </div>
            )}
            <div className="findings">
              {findings.map((f, i) => (
                <FindingCard key={f.id} finding={f} index={i + 1} />
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
