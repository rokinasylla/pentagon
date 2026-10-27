import { useEffect, useState } from "react";
import * as api from "../api/client.js";
import TopNav from "../components/TopNav.jsx";
import AdminView from "./AdminView.jsx";

const initials = (n) => (n || "?").slice(0, 2).toUpperCase();
const SITE_STATUS_LABEL = { autorise: "Autorisé", attente: "En attente", revoque: "Révoqué" };

// Conteneur Administration : récupère comptes + sites per-operator et câble
// AdminView (présentationnel) sur l'API réelle. Modèle per-operator : les sites
// sont attribués à un opérateur avec un périmètre max et une preuve ; les
// demandes d'accès (statut « attente ») se valident/refusent ici.
export default function Admin({ user, onLogout }) {
  const [users, setUsers] = useState([]);
  const [sites, setSites] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = async () => {
    try {
      const [u, s] = await Promise.all([api.adminListUsers(), api.adminListSites()]);
      setUsers(u.users || []);
      setSites(s.sites || []);
    } catch (e) {
      setError(e.message);
    }
  };
  useEffect(() => { load(); }, []);

  const act = async (fn) => {
    setBusy(true); setError("");
    try { await fn(); await load(); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  // Projection vers les formes attendues par AdminView.
  const avUsers = users.map((u) => ({
    initials: initials(u.username),
    name: u.username,
    email: "",
    role: u.role === "admin" ? "admin" : "op",
    sites: (u.sites && u.sites.length) ? u.sites.join(", ") : "Aucun site",
    status: "actif",
    statusLabel: "Actif",
  }));
  const avSites = sites.map((s) => ({
    domain: s.domain,
    by: s.by,
    date: s.date,
    operator: s.operator,
    scope: s.scope,
    status: s.status,
    statusLabel: SITE_STATUS_LABEL[s.status] || s.status,
  }));
  const operators = users.filter((u) => u.role !== "admin").map((u) => u.username);
  const siteOptions = sites.filter((s) => s.status === "autorise").map((s) => s.domain);

  const onCreateUser = ({ username, password, role, sites: picked }) =>
    act(async () => {
      await api.adminCreateUser(username, password, role);
      if (role === "user" && picked && picked.length) {
        // Attribue les sites cochés à l'opérateur en préservant leur périmètre.
        for (const domain of picked) {
          const rec = sites.find((s) => s.domain === domain);
          if (rec) {
            await api.adminAuthorizeSite(domain, {
              operator: username,
              maxCategories: rec.max_categories || [],
              proof: rec.proof || "",
            });
          }
        }
      }
    });

  const onAuthorizeSite = ({ domain, proof, maxCategories, operator, includeSubdomains }) =>
    act(() => api.adminAuthorizeSite(domain, { operator, maxCategories, proof, includeSubdomains }));
  const onRevokeSite = (domain) => {
    if (confirm(`Révoquer l'autorisation de « ${domain} » ?`)) act(() => api.adminRevokeSite(domain));
  };
  const onApprove = (domain, operator) =>
    act(() => api.adminDecideAccessRequest(domain, "approve", {
      operator,
      maxCategories: ["passive", "active_scan"],
      proof: "Validée par l'administrateur",
    }));
  const onReject = (domain) => {
    if (confirm(`Refuser la demande pour « ${domain} » ?`)) act(() => api.adminDecideAccessRequest(domain, "reject"));
  };

  return (
    <div className="page">
      <TopNav active="reglages" user={user} onLogout={onLogout} />
      {error && <div className="err" style={{ margin: "12px 24px 0" }}>{error}</div>}
      <AdminView
        user={user}
        initialSection="sites"
        users={avUsers}
        sites={avSites}
        operators={operators}
        siteOptions={siteOptions}
        busy={busy}
        onCreateUser={onCreateUser}
        onAuthorizeSite={onAuthorizeSite}
        onRevokeSite={onRevokeSite}
        onApprove={onApprove}
        onReject={onReject}
      />
    </div>
  );
}
