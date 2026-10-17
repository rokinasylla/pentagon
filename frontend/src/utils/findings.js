// Dernier re-test d'une faille, dérivé de son historique d'évidence.
// Renvoie { ok: true/false } selon « Non reproduit » vs « Toujours vulnérable »,
// ou null si la faille n'a jamais été re-testée.
export function lastRetest(finding) {
  const ev = (finding.evidence || []).filter((e) => e.stage === "retest");
  if (ev.length === 0) return null;
  const snippet = ev[ev.length - 1].snippet || "";
  return { resolved: /non reproduit/i.test(snippet), at: ev[ev.length - 1].at };
}
