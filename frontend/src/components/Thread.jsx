import { useEffect, useRef } from "react";

// Fil de conversation : messages opérateur / système, défilement auto vers le bas.
const ROLE_LABEL = { user: "Vous", assistant: "Assistant", system: "Système" };

export default function Thread({ messages }) {
  const endRef = useRef(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages]);

  return (
    <div className="thread">
      {messages.map((m, i) => (
        <div key={i} className={`msg ${m.tone || ""}`}>
          <div className="role">{ROLE_LABEL[m.role] || m.role}</div>
          <div className="body">{m.text}</div>
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}
