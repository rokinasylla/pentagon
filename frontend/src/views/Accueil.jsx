import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import * as api from "../api/client.js";
import TopNav from "../components/TopNav.jsx";
import EspaceOperateur from "./EspaceOperateur.jsx";

// Hôte nu d'une cible (pour rapprocher sites et sessions).
const host = (t) => String(t || "").replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
const RISK_MAP = { critical: "high", high: "high", medium: "medium", low: "low" };

const STATE = {
  running: { label: "En cours", color: "#B0541E" },
  done: { label: "Terminée", color: "#3C6686" },
};

// Pastilles de périmètre RoE d'après le périmètre max du site.
function roePills(cats = []) {
  const pills = [];
  if (cats.includes("passive")) pills.push({ label: "Recon", kind: "on" });
  if (cats.includes("active_scan")) pills.push({ label: "Scan actif", kind: "on" });
  pills.push(cats.includes("exploitation")
    ? { label: "Exploitation", kind: "offensive" }
    : { label: "Exploitation sur demande", kind: "dashed" });
  return pills;
}

// Conteneur de l'accueil opérateur : sites attribués (/me/sites) + sessions
// récentes (/api/jobs), câblé sur le modèle per-operator.
export default function Accueil({ user, onLogout }) {
  const navigate = useNavigate();
  const [sites, setSites] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [error, setError] = useState("");

  const load = async () => {
    try {
      const [mine, jobs] = await Promise.all([api.getMySites(), api.listSessions()]);
      setSites(mine.sites || []);
      setSessions(Array.isArray(jobs) ? jobs : (jobs.jobs || jobs.sessions || []));
    } catch (e) {
      setError(e.message);
    }
  };
  useEffect(() => { load(); }, []);

  // Dernière session connue pour un hôte (pour le risque + la date).
  const latestFor = (h) =>
    sessions.find((s) => host(s.target) === h) || null;

  const cards = sites.map((s) => {
    const last = latestFor(host(s.domain));
    const risk = last && last.overall_risk ? (RISK_MAP[last.overall_risk] || "none") : "none";
    const subtitle = last
      ? `campagne ${last.campaign_id || last.job_id || ""} · dernière session ${last.started_at || last.date || "récemment"}`
      : "aucune session pour l'instant";
    return { host: s.domain, subtitle, risk, roe: roePills(s.max_categories) };
  });

  const recent = sessions.slice(0, 6).map((s) => {
    const st = STATE[s.status] || (s.status === "running" ? STATE.running : STATE.done);
    return {
      campaign: `Campagne ${s.campaign_id || s.job_id || ""}`.trim(),
      target: s.target,
      state: st.label,
      stateColor: st.color,
      date: s.started_at || s.date || "",
    };
  });

  const onRequestAccess = async () => {
    const domain = window.prompt("Domaine du site à demander (ex. exemple.com) :");
    if (!domain || !domain.trim()) return;
    try { await api.requestAccess(domain.trim()); await load(); }
    catch (e) { setError(e.message); }
  };

  return (
    <div className="page">
      <TopNav active="accueil" user={user} onLogout={onLogout} />
      {error && <div className="err" style={{ margin: "12px 24px 0" }}>{error}</div>}
      <EspaceOperateur
        user={user}
        sites={cards}
        sessions={recent}
        onOpenSession={() => navigate("/")}
        onNewMission={() => navigate("/mission")}
        onRequestAccess={onRequestAccess}
      />
    </div>
  );
}
