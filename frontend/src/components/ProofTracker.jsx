// Tracker Détecté → Prouvé → Confirmé : met en évidence l'état atteint par la
// faille (et tous les états précédents, puisque la progression est monotone).
const ORDER = ["detected", "proven", "confirmed"];
const LABEL = { detected: "Détecté", proven: "Prouvé", confirmed: "Confirmé" };

export default function ProofTracker({ state }) {
  const current = ORDER.indexOf(state);
  return (
    <div className="tracker" aria-label={`État de preuve : ${LABEL[state] || state}`}>
      {ORDER.map((s, i) => (
        <div key={s} style={{ display: "contents" }}>
          {i > 0 && <span className="sep" />}
          <span className={`step ${s} ${i <= current ? "on" : "future"}`}>
            <span className="dot" />
            {LABEL[s]}
          </span>
        </div>
      ))}
    </div>
  );
}
