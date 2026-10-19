import { useEffect, useState } from "react";
import * as api from "../api/client.js";
import AuditPanel from "./AuditPanel.jsx";

// Verdict d'un contrôle d'en-tête manquant selon sa sévérité.
const headerVerdict = (sev) => (sev === "high" || sev === "critical" ? "expose" : "corriger");
// Verdict d'une CVE selon sa sévérité.
const cveVerdict = (sev) => (sev === "high" || sev === "critical" ? "expose" : "corriger");

// Transforme la charge utile de /audit (en-têtes, divulgation, cookies, CVE)
// en groupes par domaine attendus par AuditPanel. Les domaines non fournis par
// le back (transport, méthodes, ports, DNS) n'apparaissent simplement pas —
// ils seront remontés quand l'audit back sera enrichi (cf. ui-refonte §4).
function toGroups(audit) {
  const groups = [];

  const headers = [
    ...(audit.present_headers || []).map((h) => ({
      name: h.header, target: "en-tête", detail: h.value, reco: "conforme", v: "bon",
    })),
    ...(audit.missing_headers || []).map((h) => ({
      name: h.header, target: "en-tête", detail: h.description, reco: h.owasp, v: headerVerdict(h.severity),
    })),
  ];
  if (headers.length) groups.push({ title: "En-têtes HTTP de sécurité", lines: headers });

  const disclosure = (audit.info_disclosure || []).map((h) => ({
    name: h.header, target: "en-tête", detail: `expose « ${h.value} »`, reco: h.description, v: "expose",
  }));
  if (disclosure.length) groups.push({ title: "Divulgation d’information", lines: disclosure });

  const cookies = (audit.cookie_issues || []).map((c) => ({
    name: c.name || c.cookie || "cookie", target: "cookie", detail: c.issue || c.description || "", reco: "", v: "corriger",
  }));
  if (cookies.length) groups.push({ title: "Cookies", lines: cookies });

  const cves = (audit.cve || audit.cves || []).map((c) => ({
    name: c.product || c.component || c.cve, target: c.cve || "bannière",
    detail: c.summary || c.description || "", reco: c.recommendation || "mettre à jour",
    v: cveVerdict(c.severity),
  }));
  if (cves.length) groups.push({ title: "Corrélation CVE des composants", lines: cves });

  return groups;
}

export default function AuditView({ sessionId }) {
  const [audit, setAudit] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true); setError("");
    api.getAudit(sessionId).then(setAudit).catch((e) => setError(e.message)).finally(() => setLoading(false));
  }, [sessionId]);

  if (loading) return <div className="loading">Chargement de l'audit…</div>;
  if (error) return <div className="err">{error}</div>;
  if (!audit) return null;
  if (!audit.available) {
    return <div className="empty">Aucune donnée de durcissement pour cette session.</div>;
  }

  return <AuditPanel score={audit.security_score} groups={toGroups(audit)} />;
}
