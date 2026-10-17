import { useNavigate } from "react-router-dom";
import { Logo } from "./Brand.jsx";
import * as api from "../api/client.js";

// Rail de navigation latéral (fidèle à la maquette) : logo, items de navigation,
// puis le profil de l'opérateur en bas. `active` surligne l'item courant.
function Item({ label, icon, on, onClick }) {
  return (
    <button className={`rail-item ${on ? "on" : ""}`} onClick={onClick} title={label}>
      <span className="rail-ico" aria-hidden="true">{icon}</span>
      <span className="rail-lbl">{label}</span>
    </button>
  );
}

const ICON = {
  missions: "◆",
  sessions: "❯_",
  audits: "▣",
  rapports: "▤",
  reglages: "⚙",
};

export default function Rail({ active, user, onLogout }) {
  const navigate = useNavigate();
  const initials = (user.operator || "?").slice(0, 2).toUpperCase();

  const logout = async () => {
    try { await api.logout(); } finally { await onLogout(); }
  };

  return (
    <nav className="rail">
      <div className="rail-brand">
        <span className="rail-mark"><Logo size={22} /></span>
        <span className="rail-word">PENTAGON</span>
      </div>

      <div className="rail-nav">
        <Item label="Missions" icon={ICON.missions} on={active === "missions"}
          onClick={() => navigate("/mission")} />
        <Item label="Sessions" icon={ICON.sessions} on={active === "sessions"}
          onClick={() => navigate("/")} />
        <Item label="Audits" icon={ICON.audits} on={active === "audits"}
          onClick={() => navigate("/overview", { state: { view: "audits" } })} />
        <Item label="Rapports" icon={ICON.rapports} on={active === "rapports"}
          onClick={() => navigate("/overview", { state: { view: "reports" } })} />
        {user.role === "admin" && (
          <Item label="Réglages" icon={ICON.reglages} on={active === "reglages"}
            onClick={() => navigate("/admin")} />
        )}
      </div>

      <div className="rail-user">
        <span className="rail-avatar">{initials}</span>
        <span className="rail-id">
          <span className="rail-name">{user.operator}</span>
          <span className="rail-role">{user.role === "admin" ? "Administrateur" : "Opérateur"}</span>
        </span>
        <button className="rail-logout" onClick={logout} title="Déconnexion">⏻</button>
      </div>
    </nav>
  );
}
