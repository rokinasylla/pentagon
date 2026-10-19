import { useEffect, useRef } from "react";
import { Logo } from "./Brand.jsx";
import Icon from "./Icon.jsx";

// Fil de conversation à bulles (fidèle à l'artboard Main) : opérateur à droite,
// agent à gauche avec l'avatar PENTAGON. Les messages peuvent porter un bloc
// structuré (récit d'exploitation / refus hors-périmètre).
function RichBlock({ block }) {
  if (block.type === "refusal") {
    return (
      <div className="bubble b-agent xrefuse xblock">
        <div className="xb-title">
          <Icon name="lock" size={16} />
          {block.title}
        </div>
        <p className="xb-lead">{block.text}</p>
      </div>
    );
  }
  // type "exploit"
  return (
    <div className="bubble b-agent xblock">
      <div className="xb-title">
        <Icon name="exploit" size={16} />
        {block.title}
      </div>
      {block.lead && <p className="xb-lead">{block.lead}</p>}
      {block.steps?.length > 0 && (
        <div className="xb-steps">
          {block.steps.map((s, i) => (
            <div key={i} className="xb-step">
              <span className="xb-check"><Icon name="check" size={11} sw={3} /></span>
              <span>{s}</span>
            </div>
          ))}
        </div>
      )}
      {block.impact && (
        <div className="xb-impact">
          <Icon name="shieldCheck" size={17} />
          <p><strong>Impact démontré.</strong> {block.impact}</p>
        </div>
      )}
      {block.reason && <p className="xb-lead">{block.reason}</p>}
    </div>
  );
}

export default function Chat({ messages, userInitials = "?" }) {
  const endRef = useRef(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages]);

  return (
    <div className="chat">
      {messages.map((m, i) => {
        const agent = m.role !== "user";
        return (
          <div key={i} className={`cmsg ${agent ? "from-agent" : "from-user"}`}>
            <span className={`cav ${agent ? "agent" : "user"}`} aria-hidden="true">
              {agent ? <Logo size={17} /> : userInitials}
            </span>
            <div className="cmsg-main">
              <div className="cmsg-who">
                {agent ? <><b>PENTAGON</b> agent</> : "Opérateur"}
              </div>
              {m.block ? (
                <RichBlock block={m.block} />
              ) : (
                <div className={`bubble ${agent ? "b-agent" : "b-user"} ${m.tone || ""}`}>
                  {m.text}
                </div>
              )}
            </div>
          </div>
        );
      })}
      <div ref={endRef} />
    </div>
  );
}
