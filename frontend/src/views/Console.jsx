import { useEffect, useState } from "react";
import * as api from "../api/client.js";
import Brand from "../components/Brand.jsx";
import FindingCard from "../components/FindingCard.jsx";
import FindingDrawer from "../components/FindingDrawer.jsx";
import CommandBar from "../components/CommandBar.jsx";
import Thread from "../components/Thread.jsx";

const PREPROMPTS = [
  "/exploit 1",
  "/confirm 1",
  "/audit",
];

export default function Console({ user, onLogout }) {
  const [sessions, setSessions] = useState([]);
  const [activeId, setActiveId] = useState("");
  const [findings, setFindings] = useState([]);
  const [loadingF, setLoadingF] = useState(false);
  const [error, setError] = useState("");
  const [messages, setMessages] = useState([]);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState(null); // faille ouverte dans le drawer

  const pushMsg = (role, text, tone = "") =>
    setMessages((m) => [...m, { role, text, tone }]);

  // Inventaire des campagnes au montage.
  useEffect(() => {
    (async () => {
      try {
        const data = await api.listSessions();
        const jobs = data.jobs || [];
        setSessions(jobs);
        const first = jobs.find((j) => j.has_summary) || jobs[0];
        if (first) setActiveId(first.job_id);
      } catch (err) {
        setError(err.message);
      }
    })();
  }, []);

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
  const exploit = async (finding, mode) => {
    setBusy(true);
    pushMsg("user", `${mode === "confirm" ? "/confirm" : "/exploit"} ${finding.title}`);
    try {
      const res = await api.exploitFinding(activeId, finding.id, mode);
      if (res.finding) mergeFinding(res.finding);
      pushMsg("assistant", res.reason || `Faille ${res.status}.`,
        res.status === "confirmed" ? "good" : "");
    } catch (err) {
      // 403 (hors RoE) ou autre : message propre.
      pushMsg("system", err.message || "Exploitation refusée.", "warn");
    } finally {
      setBusy(false);
    }
  };

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
          <select id="sess" value={activeId} onChange={(e) => setActiveId(e.target.value)}>
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
        {/* ─── FIL ─── */}
        <section className="pane fil">
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

        {/* ─── CANEVAS ─── */}
        <section className="pane canevas">
          <div className="pane-head">
            Findings {findings.length > 0 && `(${findings.length})`}
          </div>
          <div className="pane-body">
            {error && <div className="err">{error}</div>}
            {loadingF && <div className="loading">Chargement des findings…</div>}
            {!loadingF && !error && findings.length === 0 && (
              <div className="empty">Aucune faille à afficher pour cette session.</div>
            )}
            <div className="findings">
              {findings.map((f, i) => (
                <FindingCard
                  key={f.id}
                  finding={f}
                  index={i + 1}
                  busy={busy}
                  onOpen={setSelected}
                  onConfirm={(fd) => exploit(fd, "confirm")}
                />
              ))}
            </div>
          </div>
        </section>
      </div>

      <FindingDrawer
        finding={selected}
        busy={busy}
        onProve={(f) => exploit(f, "prove")}
        onConfirm={(f) => exploit(f, "confirm")}
        onClose={() => setSelected(null)}
      />
    </div>
  );
}
