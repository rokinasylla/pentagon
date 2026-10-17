import { useNavigate } from "react-router-dom";
import { Logo } from "./Brand.jsx";
import * as api from "../api/client.js";

// Barre de navigation horizontale (fidèle aux artboards Mission / Admin) :
// logo + liens + pastille profil. `active` surligne l'onglet courant.
export default function TopNav({ active, user, onLogout }) {
  const navigate = useNavigate();
  const logout = async () => {
    try { await api.logout(); } finally { onLogout && (await onLogout()); }
  };
  const initials = (user.operator || "?").slice(0, 2).toUpperCase();
  const links = [
    { key: "missions", label: "Missions", go: () => navigate("/mission") },
    { key: "sessions", label: "Sessions", go: () => navigate("/") },
    { key: "audits", label: "Audits", go: () => navigate("/overview", { state: { view: "audits" } }) },
    { key: "rapports", label: "Rapports", go: () => navigate("/overview", { state: { view: "reports" } }) },
  ];
  if (user.role === "admin")
    links.push({ key: "reglages", label: "Réglages", go: () => navigate("/admin") });

  return (
    <header className="topnav">
      <button className="tn-brand" onClick={() => navigate("/")}>
        <span className="tn-mark"><Logo size={26} /></span>
        <span className="tn-word">PENTAGON</span>
      </button>
      <nav className="tn-nav">
        {links.map((l) => (
          <button key={l.key} className={`tn-link ${active === l.key ? "on" : ""}`} onClick={l.go}>
            {l.label}
          </button>
        ))}
      </nav>
      <div className="tn-user">
        <span className="tn-avatar">{initials}</span>
        <span className="tn-name">{user.operator}</span>
        <span className="tn-role">{user.role === "admin" ? "Administrateur" : "Opérateur"}</span>
        {onLogout && (
          <button className="tn-logout" onClick={logout} title="Déconnexion">⏻</button>
        )}
      </div>
    </header>
  );
}
