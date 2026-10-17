import { useState } from "react";
import * as api from "../api/client.js";
import { Logo } from "../components/Brand.jsx";

// Connexion — écran scindé fidèle à la maquette : panneau de marque sombre à
// gauche, formulaire à droite. Le rôle est déterminé par le compte (pas de
// choix de profil en production).
export default function Login({ onAuthed }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await api.login(username.trim(), password);
      await onAuthed();
    } catch (err) {
      setError(err.message || "Connexion impossible.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-split">
      {/* Panneau de marque */}
      <aside className="brand-panel">
        <div className="brand-logo">
          <span className="bp-mark"><Logo size={34} /></span>
          <span className="bp-word">PENTAGON</span>
        </div>
        <div className="bp-pitch">
          <h1>Un agent qui prouve ce qu'il avance.</h1>
          <p>
            Chaque vulnérabilité est accompagnée de la démonstration concrète qui
            l'établit — détecter en prouvant, jamais ravager.
          </p>
        </div>
        <div className="bp-foot">
          <span>Détecté → Prouvé → Confirmé</span>
          <span>RoE · fermé par défaut</span>
        </div>
      </aside>

      {/* Panneau formulaire */}
      <section className="form-panel">
        <form className="login-form" onSubmit={submit}>
          <h2>Connexion</h2>
          <p className="sub">
            Accès réservé aux comptes habilités. Votre profil — opérateur ou
            administrateur — détermine ce à quoi vous accédez après connexion.
          </p>

          <label className="fld-label" htmlFor="u">Identifiant</label>
          <div className="fld">
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <rect x="3" y="5" width="18" height="14" rx="2.5" stroke="currentColor" strokeWidth="1.8" />
              <path d="M4 7l8 6 8-6" stroke="currentColor" strokeWidth="1.8" />
            </svg>
            <input id="u" autoComplete="username" value={username}
              onChange={(e) => setUsername(e.target.value)} autoFocus
              placeholder="votre identifiant" />
          </div>

          <label className="fld-label" htmlFor="p">Mot de passe</label>
          <div className="fld">
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" strokeWidth="1.8" />
              <path d="M8 11V8a4 4 0 018 0v3" stroke="currentColor" strokeWidth="1.8" />
            </svg>
            <input id="p" type="password" autoComplete="current-password" value={password}
              onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
          </div>

          <button className="primary submit" type="submit" disabled={busy}>
            {busy ? "Connexion…" : "Se connecter"}
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M5 12h13M12 5l7 7-7 7" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>
          {error && <div className="err">{error}</div>}

          <p className="foot-note">
            Les sessions expirent après inactivité. Rôles séparés : administrateur
            (comptes & droits) et opérateur (campagnes).
          </p>
        </form>
      </section>
    </div>
  );
}
