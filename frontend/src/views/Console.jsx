import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import * as api from "../api/client.js";
import Rail from "../components/Rail.jsx";
import FindingCard from "../components/FindingCard.jsx";
import FindingDrawer from "../components/FindingDrawer.jsx";
import CommandBar from "../components/CommandBar.jsx";
import Thread from "../components/Thread.jsx";
import AuditView from "../components/AuditView.jsx";
import ReportView from "../components/ReportView.jsx";

const PREPROMPTS = [
  "/exploit 1",
  "/confirm 1",
  "/audit",
];

export default function Console({ user, onLogout }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [sessions, setSessions] = useState([]);
  const [activeId, setActiveId] = useState("");
  const [findings, setFindings] = useState([]);
  const [loadingF, setLoadingF] = useState(false);
  const [error, setError] = useState("");
  const [messages, setMessages] = useState([]);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState(null); // faille ouverte dans le drawer
  const [tab, setTab] = useState("findings"); // onglet du canevas
  const [busyFinding, setBusyFinding] = useState(""); // id de la faille en cours d'action
  const [cardMsg, setCardMsg] = useState({}); // retour par carte {id: {text, tone}}

  const pushMsg = (role, text, tone = "") =>
    setMessages((m) => [...m, { role, text, tone }]);

  // Inventaire des campagnes au montage.
  useEffect(() => {
    (async () => {
      try {
        const data = await api.listSessions();
        // On NE sélectionne AUCUNE campagne d'office : un nouvel utilisateur
        // (ou sans campagne) voit une console vide, pas les failles d'autrui.
        setSessions(data.jobs || []);
      } catch (err) {
        setError(err.message);
      }
    })();
  }, []);

  // Pré-sélection depuis la vue d'ensemble (session + onglet).
  useEffect(() => {
    const st = location.state;
    if (st && st.sessionId) {
      setActiveId(st.sessionId);
      if (st.tab) setTab(st.tab);
      // Nettoie l'état de navigation pour ne pas le ré-appliquer.
      navigate(".", { replace: true, state: null });
    }
  }, [location.state, navigate]);

  // Findings de la session active.
  useEffect(() => {
    if (!activeId) {
      setFindings([]);
      return;
    }
    setLoadingF(true);
    setError("");
    setMessages([
      { role: "assistant", text: "Session chargée. Tapez /help pour les commandes, ou posez votre question." },
    ]);
    api
      .getFindings(activeId)
      .then((data) => setFindings(data.findings || []))
      .catch((err) => setError(err.message))
      .finally(() => setLoadingF(false));
  }, [activeId]);

  // Fusionne une version mise à jour d'une faille (tracker live + drawer).
  const mergeFinding = (updated) => {
    if (!updated || !updated.id) return;
    setFindings((fs) => fs.map((f) => (f.id === updated.id ? updated : f)));
    setSelected((s) => (s && s.id === updated.id ? updated : s));
  };

  // Envoi d'une commande (slash ou langage naturel) → POST /command.
  const runCommand = async (raw) => {
    pushMsg("user", raw);
    setBusy(true);
    try {
      const o = await api.sendCommand(activeId, raw);
      if (o.status === "help") {
        pushMsg("system", o.help);
      } else if (["unknown", "needs_index", "needs_arg", "denied", "handler_error"].includes(o.status)) {
        pushMsg("system", o.reason + (o.help ? `\n\n${o.help}` : ""), "warn");
      } else {
        const r = o.result || {};
        if (r.finding) {
          mergeFinding(r.finding);
          pushMsg("assistant", r.reason || `Faille ${r.status}.`,
            r.status === "confirmed" ? "good" : "");
        } else if (r.directive) {
          pushMsg("assistant", r.message);
        } else if (r.audit) {
          pushMsg("assistant",
            `Audit — risque ${r.audit.overall_risk}, ${r.audit.proven_count} prouvée(s), ${r.audit.detected_count} détectée(s).`);
        } else {
          pushMsg("assistant", `Commande « ${o.action} » exécutée.`);
        }
      }
    } catch (err) {
      pushMsg("system", err.message || "Commande impossible.", "warn");
    } finally {
      setBusy(false);
    }
  };

  // Exploitation à la demande d'une faille (prove|confirm) → POST /exploit.
  const setMsgFor = (id, text, tone = "") =>
    setCardMsg((m) => ({ ...m, [id]: { text, tone } }));

  const exploit = async (finding, mode) => {
    setBusyFinding(finding.id);
    setMsgFor(finding.id, "Exploitation en cours…", "");
    pushMsg("user", `${mode === "confirm" ? "/confirm" : "/exploit"} ${finding.title}`);
    try {
      const res = await api.exploitFinding(activeId, finding.id, mode);
      if (res.finding) mergeFinding(res.finding);
      const good = res.status === "confirmed" || res.status === "proven";
      pushMsg("assistant", res.reason || `Faille ${res.status}.`, good ? "good" : "warn");
      setMsgFor(finding.id, res.reason || `Résultat : ${res.status}.`, good ? "good" : "warn");
    } catch (err) {
      const text = err.status === 403
        ? "Bloqué : ce site n'est pas autorisé (hors périmètre RoE)."
        : (err.message || "Exploitation refusée.");
      pushMsg("system", text, "warn");
      setMsgFor(finding.id, text, "warn");
    } finally {
      setBusyFinding("");
    }
  };

  // Re-test ciblé d'une faille (UI-4) → POST /retest.
  const retest = async (finding) => {
    setBusyFinding(finding.id);
    setMsgFor(finding.id, "Re-test en cours…", "");
    pushMsg("user", `/retest ${finding.title}`);
    try {
      const res = await api.retestFinding(activeId, finding.id);
      if (res.finding) mergeFinding(res.finding);
      const tone = res.still_vulnerable === false ? "good" : "warn";
      pushMsg("assistant", res.reason || "Re-test effectué.", tone);
      setMsgFor(finding.id, res.reason || "Re-test effectué.", tone);
    } catch (err) {
      const text = err.status === 403
        ? "Bloqué : ce site n'est pas autorisé (hors périmètre RoE)."
        : (err.message || "Re-test refusé.");
      pushMsg("system", text, "warn");
      setMsgFor(finding.id, text, "warn");
    } finally {
      setBusyFinding("");
    }
  };

  const doLogout = async () => {
    try {
      await api.logout();
    } finally {
      await onLogout();
    }
  };

  const activeSession = sessions.find((s) => s.job_id === activeId);

  return (
    <div className="layout">
      <Rail active="sessions" user={user} onLogout={onLogout} />

      <div className="main">
        <div className="panes">
          {/* ─── FIL ─── */}
          <section className="pane fil">
            {/* En-tête « Session active » */}
            <div className="session-head">
              <div className="sh-row">
                <span className="sh-eyebrow">Session active</span>
                <select
                  className="sh-switch"
                  value={activeId}
                  onChange={(e) => setActiveId(e.target.value)}
                  aria-label="Changer de session"
                >
                  <option value="">
                    {sessions.length === 0 ? "Aucune campagne" : "— choisir une campagne —"}
                  </option>
                  {sessions.map((s) => {
                    const d = s.started_at ? s.started_at.slice(0, 10) : "";
                    return (
                      <option key={s.job_id} value={s.job_id}>
                        {s.target || s.job_id}{d && ` · ${d}`}
                      </option>
                    );
                  })}
                </select>
              </div>
              {activeSession && (
                <>
                  <div className="sh-target">{activeSession.target || activeId}</div>
                  <div className="sh-meta">
                    <span className={`risk ${activeSession.overall_risk}`}>
                      risque {activeSession.overall_risk}
                    </span>
                    <span className="sh-counts">
                      {activeSession.proven_count ?? 0} prouvées · {activeSession.detected_count ?? 0} détectées
                    </span>
                  </div>
                </>
              )}
              <button className="primary sm sh-new" onClick={() => navigate("/mission")}>
                + Nouvelle mission
              </button>
            </div>

            <div className="pane-head">Fil</div>
            <div className="pane-body">
              <Thread messages={messages} />
            </div>
          <div className="preprompts" style={{ padding: "0 18px 10px" }}>
            {PREPROMPTS.map((p) => (
              <button
                key={p}
                className="chip"
                type="button"
                disabled={busy || !activeId}
                onClick={() => runCommand(p)}
              >
                {p}
              </button>
            ))}
          </div>
          <CommandBar onSubmit={runCommand} busy={busy || !activeId} />
        </section>

        {/* ─── CANEVAS (onglets) ─── */}
        <section className="pane canevas">
          <div className="pane-head tabs" role="tablist">
            <button
              className={`tab ${tab === "findings" ? "on" : ""}`}
              role="tab"
              aria-selected={tab === "findings"}
              onClick={() => setTab("findings")}
            >
              Findings {findings.length > 0 && <span className="tab-n">{findings.length}</span>}
            </button>
            <button
              className={`tab ${tab === "audit" ? "on" : ""}`}
              role="tab"
              aria-selected={tab === "audit"}
              onClick={() => setTab("audit")}
            >
              Audit
            </button>
            <button
              className={`tab ${tab === "report" ? "on" : ""}`}
              role="tab"
              aria-selected={tab === "report"}
              onClick={() => setTab("report")}
            >
              Rapport
            </button>
          </div>

          <div className="pane-body">
            {tab === "findings" && (
              <>
                {error && <div className="err">{error}</div>}
                {!activeId && !loadingF && (
                  <div className="welcome">
                    <div className="welcome-mark">◆</div>
                    <h3>Aucune campagne ouverte</h3>
                    <p>
                      Lancez une mission pour découvrir les vulnérabilités de votre
                      site. Les failles trouvées s'afficheront ici.
                    </p>
                    <button className="primary" onClick={() => navigate("/mission")}>
                      + Nouvelle mission
                    </button>
                    {sessions.length > 0 && (
                      <p className="welcome-hint">
                        …ou choisissez une campagne passée dans le sélecteur ci-dessus.
                      </p>
                    )}
                  </div>
                )}
                {loadingF && <div className="loading">Chargement des findings…</div>}
                {activeId && !loadingF && !error && findings.length === 0 && (
                  <div className="empty">Aucune faille à afficher pour cette session.</div>
                )}
                <div className="findings">
                  {findings.map((f, i) => (
                    <FindingCard
                      key={f.id}
                      finding={f}
                      index={i + 1}
                      acting={busyFinding === f.id}
                      msg={cardMsg[f.id]}
                      onOpen={setSelected}
                      onProve={(fd) => exploit(fd, "prove")}
                      onConfirm={(fd) => exploit(fd, "confirm")}
                      onDismiss={(fd) => setFindings((list) => list.filter((x) => x.id !== fd.id))}
                    />
                  ))}
                </div>
              </>
            )}
            {tab === "audit" && <AuditView sessionId={activeId} />}
            {tab === "report" && <ReportView sessionId={activeId} />}
            </div>
          </section>
        </div>
      </div>

      <FindingDrawer
        finding={selected}
        busy={!!busyFinding}
        onProve={(f) => exploit(f, "prove")}
        onConfirm={(f) => exploit(f, "confirm")}
        onRetest={retest}
        onClose={() => setSelected(null)}
      />
    </div>
  );
}
