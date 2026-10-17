import { useState } from "react";
import * as api from "../api/client.js";
import Brand from "../components/Brand.jsx";

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
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <Brand showSub={false} />
        <h1>Connexion</h1>
        <p className="hint">
          Console offensive — accès réservé aux opérateurs autorisés.
        </p>

        <div className="field">
          <label htmlFor="u">Identifiant</label>
          <input
            id="u"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
          />
        </div>
        <div className="field">
          <label htmlFor="p">Mot de passe</label>
          <input
            id="p"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        <button className="primary" type="submit" disabled={busy} style={{ width: "100%" }}>
          {busy ? "Connexion…" : "Se connecter"}
        </button>
        {error && <div className="err">{error}</div>}
      </form>
    </div>
  );
}
