// Spécifications des commandes de la console — miroir du dispatcher backend
// (pentagon/core/command_dispatcher.py). Sert à l'autocomplétion et à l'aide.
export const COMMANDS = [
  { name: "scan", usage: "/scan", desc: "Lance une reconnaissance et un scan" },
  { name: "exploit", usage: "/exploit <n>", desc: "Prouve la faille n° <n>", arg: "index" },
  { name: "confirm", usage: "/confirm <n>", desc: "Confirme la faille n° <n> (impact réel)", arg: "index" },
  { name: "audit", usage: "/audit", desc: "Posture de durcissement du serveur" },
  { name: "report", usage: "/report", desc: "Génère le rapport de campagne" },
  { name: "scope", usage: "/scope <cible>", desc: "Demande l'extension du périmètre", arg: "text" },
  { name: "stop", usage: "/stop", desc: "Arrête la campagne en cours" },
  { name: "help", usage: "/help", desc: "Affiche les commandes disponibles" },
];

// Filtre les commandes dont le nom commence par le texte saisi après « / ».
export function matchCommands(input) {
  const text = (input || "").trim();
  if (!text.startsWith("/")) return [];
  const token = text.slice(1).split(/\s+/)[0].toLowerCase();
  if (text.slice(1).includes(" ")) return []; // argument en cours de saisie
  return COMMANDS.filter((c) => c.name.startsWith(token));
}
