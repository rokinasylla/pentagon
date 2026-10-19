import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import * as api from "../api/client.js";
import TopNav from "../components/TopNav.jsx";
import SessionHeader from "../components/SessionHeader.jsx";
import Chat from "../components/Chat.jsx";
import CommandBar from "../components/CommandBar.jsx";
import FindingCard from "../components/FindingCard.jsx";
import FindingDrawer from "../components/FindingDrawer.jsx";
import AuditView from "../components/AuditView.jsx";
import ReportView from "../components/ReportView.jsx";
import Icon from "../components/Icon.jsx";

// Suggestions en langage naturel (comme l'artboard) — envoyées telles quelles
// au dispatcher de commandes, qui gère le NL et les slashs.
const SUGGEST = [
  "Suis-je protégé ?",
  "Explique la faille 1 simplement",
  "Lance un audit serveur",
  "Génère le rapport",
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
  const [selected, setSelected] = useState(null); // faille ouverte dans le détail
  const [tab, setTab] = useState("findings"); // onglet du canevas
  const [busyFinding, setBusyFinding] = useState(""); // id de la faille en action
  const [cardMsg, setCardMsg] = useState({}); // retour par carte {id:{text,tone}}

  const initials = (user.operator || "?").slice(0, 2).toUpperCase();
  const pushMsg = (role, text, tone = "") =>
    setMessages((m) => [...m, { role, text, tone }]);
  const pushBlock = (block) =>
    setMessages((m) => [...m, { role: "assistant", block }]);

  // Inventaire des campagnes au montage. On NE sélectionne AUCUNE campagne
  // d'office : un nouvel utilisateur voit une console vide, pas les failles d'autrui.
  useEffect(() => {
    (async () => {
      try {
        const data = await api.listSessions();
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
      navigate(".", { replace: true, state: null });
    }
  }, [location.state, navigate]);

  // Findings de la session active.
  useEffect(() => {
    if (!activeId) {
      setFindings([]);
      setMessages([]);
      return;
    }
    setLoadingF(true);
    setError("");
    setMessages([
      { role: "assistant", text: "Session chargée. Décrivez une intention, ou tapez / pour une commande." },
    ]);
    api
      .getFindings(activeId)
      .then((data) => setFindings(data.findings || []))
      .catch((err) => setError(err.message))
      .finally(() => setLoadingF(false));
  }, [activeId]);

  const mergeFinding = (updated) => {
    if (!updated || !updated.id) return;
    setFindings((fs) => fs.map((f) => (f.id === updated.id ? updated : f)));
    setSelected((s) => (s && s.id === updated.id ? updated : s));
  };

  // Commande (slash ou langage naturel) → POST /command.
  const runCommand = async (raw) => {
    pushMsg("user", raw);
    setBusy(true);
    try {
      const o = await api.sendCommand(activeId, raw);
      if (o.status === "help") {
        pushMsg("assistant", o.help);
      } else if (["unknown", "needs_index", "needs_arg", "denied", "handler_error"].includes(o.status)) {
        pushMsg("system", o.reason + (o.help ? `\n\n${o.help}` : ""), "warn");
      } else {
        const r = o.result || {};
        if (r.finding) {
          mergeFinding(r.finding);
          pushMsg("assistant", r.reason || `Faille ${r.status}.`, r.status === "confirmed" ? "good" : "");
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

  const setMsgFor = (id, text, tone = "") =>
    setCardMsg((m) => ({ ...m, [id]: { text, tone } }));

  // Exploitation à la demande (prove|confirm) → POST /exploit. Le récit riche
  // s'écrit dans le fil ; la carte reçoit un retour synthétique.
  const exploit = async (finding, mode) => {
    setBusyFinding(finding.id);
    setMsgFor(finding.id, mode === "confirm" ? "Confirmation en cours…" : "Preuve en cours…", "");
    pushMsg("user", `${mode === "confirm" ? "/confirm" : "/exploit"} ${finding.title}`);
    try {
      const res = await api.exploitFinding(activeId, finding.id, mode);
      if (res.finding) mergeFinding(res.finding);
      const ok = res.status === "confirmed" || res.status === "proven";
      const confirmed = res.status === "confirmed";
      pushBlock({
        type: "exploit",
        confirmed,
        title: confirmed
          ? `Confirmation par exploitation — ${finding.title}`
          : ok
          ? `Preuve automatique — ${finding.title}`
          : `Exploitation — ${finding.title}`,
        lead: confirmed
          ? "Exploitation pilotée comme un utilisateur réel — bornée à la preuve, sans exfiltration ni écriture destructive."
          : "",
        impact: ok ? (res.snippet || res.reason || "Faille démontrée.") : "",
        reason: ok ? "" : (res.reason || "Rien de reproductible."),
      });
      setMsgFor(finding.id, res.reason || `Résultat : ${res.status}.`, ok ? "good" : "warn");
    } catch (err) {
      if (err.status === 403) {
        pushBlock({
          type: "refusal",
          title: "Action refusée — hors périmètre",
          text: "Cet actif n'appartient pas au périmètre autorisé de cette mission. Le garde-fou bloque l'action avant exécution (fermé par défaut).",
        });
        setMsgFor(finding.id, "Bloqué : ce site n'est pas autorisé (hors périmètre RoE).", "warn");
      } else {
        pushMsg("system", err.message || "Exploitation refusée.", "warn");
        setMsgFor(finding.id, err.message || "Exploitation refusée.", "warn");
      }
    } finally {
      setBusyFinding("");
    }
  };

  // Re-test ciblé d'une faille → POST /retest.
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
    try { await api.logout(); } finally { await onLogout(); }
  };

  const activeSession = sessions.find((s) => s.job_id === activeId);

  return (
    <div className="page">
      <TopNav active="sessions" user={user} onLogout={doLogout} />
      <SessionHeader
        activeSession={activeSession}
        sessions={sessions}
        activeId={activeId}
        onSelect={setActiveId}
      />

      <div className="workspace">
        {/* ─── CONVERSATION ─── */}
        <section className="conv">
          <div className="conv-scroll">
            {!activeId ? (
              <div className="welcome">
                <div className="welcome-mark"><Icon name="sessions" size={30} /></div>
                <h3>Aucune session ouverte</h3>
                <p>
                  Choisissez une campagne dans le bandeau ci-dessus, ou lancez une
                  mission pour découvrir les vulnérabilités de votre site.
                </p>
                <button className="primary" onClick={() => navigate("/mission")}>
                  Nouvelle mission
                </button>
              </div>
            ) : (
              <Chat messages={messages} userInitials={initials} />
            )}
          </div>

          <div className="composer">
            <div className="composer-chips">
              {SUGGEST.map((s) => (
                <button key={s} className="chip" type="button" disabled={busy || !activeId} onClick={() => runCommand(s)}>
                  {s}
                </button>
              ))}
            </div>
            <CommandBar onSubmit={runCommand} busy={busy || !activeId} />
            <div className="composer-hint">
              ⌘⏎ envoyer · / affiche les commandes — /scan /exploit /confirm /audit /report /scope /stop
            </div>
          </div>
        </section>

        {/* ─── CANEVAS (onglets) ─── */}
        <section className="canvas">
          <div className="canvas-tabs" role="tablist">
            <button className={`ctab ${tab === "findings" ? "on" : ""}`} role="tab"
              aria-selected={tab === "findings"} onClick={() => setTab("findings")}>
              Findings {findings.length > 0 && <span className="tab-n">{findings.length}</span>}
            </button>
            <button className={`ctab ${tab === "audit" ? "on" : ""}`} role="tab"
              aria-selected={tab === "audit"} onClick={() => setTab("audit")}>
              Audit
            </button>
            <button className={`ctab ${tab === "report" ? "on" : ""}`} role="tab"
              aria-selected={tab === "report"} onClick={() => setTab("report")}>
              Rapport
            </button>
            {tab === "findings" && findings.length > 0 && (
              <span className="canvas-sort">Tri : sévérité ↓</span>
            )}
          </div>

          <div className="canvas-body">
            {tab === "findings" && (
              <>
                {error && <div className="err">{error}</div>}
                {!activeId && !loadingF && (
                  <div className="empty">Ouvrez une session pour voir ses vulnérabilités.</div>
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
