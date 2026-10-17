import { useState, useRef, useEffect } from "react";
import { matchCommands } from "../constants/commands.js";

// Barre de commandes : saisie slash OU langage naturel, avec autocomplétion des
// commandes slash. Envoi via onSubmit (→ POST /command côté Console).
export default function CommandBar({ onSubmit, busy }) {
  const [value, setValue] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef(null);

  const suggestions = matchCommands(value);
  const showSug = suggestions.length > 0 && document.activeElement === inputRef.current;

  useEffect(() => {
    setActive(0);
  }, [value]);

  const complete = (cmd) => {
    // Complète avec l'usage : si la commande attend un argument, on laisse le
    // curseur après l'espace ; sinon on peut envoyer directement.
    const next = cmd.arg ? `/${cmd.name} ` : `/${cmd.name}`;
    setValue(next);
    inputRef.current?.focus();
  };

  const send = () => {
    const raw = value.trim();
    if (!raw || busy) return;
    onSubmit(raw);
    setValue("");
  };

  const onKeyDown = (e) => {
    if (showSug && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
      e.preventDefault();
      setActive((a) =>
        e.key === "ArrowDown"
          ? (a + 1) % suggestions.length
          : (a - 1 + suggestions.length) % suggestions.length
      );
      return;
    }
    if (showSug && e.key === "Tab") {
      e.preventDefault();
      complete(suggestions[active]);
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      if (showSug && suggestions.length === 1 && suggestions[0].arg) {
        complete(suggestions[0]);
      } else {
        send();
      }
    }
  };

  return (
    <div className="cmdbar-wrap">
      {showSug && (
        <ul className="cmd-suggest" role="listbox">
          {suggestions.map((c, i) => (
            <li
              key={c.name}
              className={i === active ? "on" : ""}
              onMouseDown={(e) => {
                e.preventDefault();
                complete(c);
              }}
            >
              <span className="cmd-usage">{c.usage}</span>
              <span className="cmd-desc">{c.desc}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="cmdbar">
        <input
          ref={inputRef}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="/exploit 1 · ou écrivez en langage naturel…"
          aria-label="Barre de commande"
          disabled={busy}
        />
        <button className="primary" onClick={send} disabled={busy || !value.trim()}>
          {busy ? "…" : "Envoyer"}
        </button>
      </div>
    </div>
  );
}
