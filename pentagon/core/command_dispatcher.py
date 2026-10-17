"""
Dispatcher de commandes pour la console PENTAGON (Lot UI-2).

Relie la barre de commandes de la console au MOTEUR : il traduit aussi bien
les commandes slash (`/scan`, `/exploit 3`, `/confirm 2`, `/audit`, `/report`,
`/scope <cible>`, `/stop`) que leurs formulations NATURELLES (« lance un scan »,
« exploite la faille 3 », « confirme la 2 », « génère le rapport »…) en une
ACTION structurée, puis la route vers un handler.

Deux garde-fous repris du reste du système :
  - DENY-BY-DEFAULT : chaque action offensive (scan actif, exploitation) est
    RE-VÉRIFIÉE par le RoE avant d'atteindre son handler ; sans périmètre
    injecté, tout est refusé.
  - séparation analyse / exécution : ce module ne fait qu'ANALYSER le texte et
    ROUTER ; il n'attaque rien lui-même. Les handlers (injectés) portent l'effet.

Le parsing est PUR (aucun réseau, aucun LLM) : `parse_command` est testable
hors ligne. Le `CommandDispatcher` prend ses handlers et son contrôle RoE en
injection, donc il l'est aussi.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable


# --- Actions reconnues ----------------------------------------------------
SCAN = "scan"
EXPLOIT = "exploit"
CONFIRM = "confirm"
AUDIT = "audit"
REPORT = "report"
SCOPE = "scope"
STOP = "stop"
HELP = "help"
UNKNOWN = "unknown"

KNOWN_ACTIONS = (SCAN, EXPLOIT, CONFIRM, AUDIT, REPORT, SCOPE, STOP, HELP)

# Actions qui exigent un numéro de faille (1-based, tel que l'opérateur le voit).
ACTIONS_NEED_INDEX = (EXPLOIT, CONFIRM)
# Actions qui exigent un argument texte (ex. la cible à ajouter au périmètre).
ACTIONS_NEED_ARG = (SCOPE,)

# Catégorie d'action RoE à RE-VÉRIFIER avant exécution. Les actions absentes
# de ce mapping ne touchent pas la cible (lecture de résultats, aide, arrêt) et
# ne déclenchent pas de contrôle offensif. `scope` n'y est PAS : l'extension de
# périmètre relève d'une gouvernance dédiée, portée par son propre handler.
ACTION_ROE_CATEGORY: dict[str, str] = {
    SCAN: "active_scan",
    EXPLOIT: "exploitation",
    CONFIRM: "exploitation",
}

# --- Formulations naturelles → action ------------------------------------
# Chaque action liste des mots-clés (minuscules, sans accent après
# normalisation). On retient l'action dont le mot-clé apparaît LE PLUS TÔT
# dans la phrase ; à égalité, l'ordre de priorité ci-dessous tranche.
NL_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    (STOP, ("stop", "arrete", "stoppe", "annule", "interromps", "interrompre")),
    (CONFIRM, ("confirme", "confirmer", "confirmation", "demontre", "demonstration",
               "prouve reellement")),
    (EXPLOIT, ("exploite", "exploiter", "exploitation", "attaque", "attaquer")),
    (SCAN, ("scanne", "scanner", "scan", "lance l'analyse", "lancer un scan",
            "demarre le scan", "cartographie")),
    (AUDIT, ("audit", "durcissement", "hardening", "posture")),
    (REPORT, ("rapport", "report", "compte rendu", "compte-rendu", "livrable")),
    (SCOPE, ("perimetre", "scope", "autorise la cible", "ajoute la cible",
             "etendre le perimetre")),
    (HELP, ("aide", "help", "commandes disponibles", "que peux-tu",
            "quelles commandes")),
]

# Formulations d'extension de périmètre : on en retire la cible (le reste).
_SCOPE_STRIP = re.compile(
    r"\b(ajoute|ajouter|autorise|autoriser|etends?|etendre|inclure|inclus)\b"
    r"|\b(la\s+cible|au\s+perimetre|le\s+perimetre|perimetre|scope)\b",
    re.IGNORECASE,
)


@dataclass
class Command:
    """Intention structurée issue d'un texte de commande."""

    action: str
    index: int | None = None   # numéro de faille (1-based) pour exploit/confirm
    arg: str = ""              # argument texte (ex. cible pour scope)
    raw: str = ""
    extras: dict[str, Any] = field(default_factory=dict)


def _strip_accents(text: str) -> str:
    """Normalisation ASCII simple pour comparer les mots-clés sans accents."""
    table = str.maketrans(
        "àâäáãçéèêëíìîïñóòôöõúùûüýÿ",
        "aaaaaceeeeiiiinooooouuuuyy",
    )
    return text.translate(table)


def _first_int(text: str) -> int | None:
    m = re.search(r"\d+", text)
    return int(m.group()) if m else None


def parse_command(raw: str) -> Command:
    """
    Analyse un texte en une `Command`. PUR : aucune exécution.

    Reconnaît d'abord la forme slash (`/action args`), sinon tente une
    correspondance en langage naturel. Renvoie action=UNKNOWN si rien ne
    correspond.
    """
    text = (raw or "").strip()
    if not text:
        return Command(action=UNKNOWN, raw=raw or "")

    if text.startswith("/"):
        return _parse_slash(text, raw)
    return _parse_natural(text, raw)


def _parse_slash(text: str, raw: str) -> Command:
    body = text[1:].strip()
    if not body:
        return Command(action=UNKNOWN, raw=raw)
    parts = body.split(maxsplit=1)
    name = _strip_accents(parts[0].lower())
    rest = parts[1].strip() if len(parts) > 1 else ""

    # alias courants
    aliases = {"scanner": SCAN, "exploiter": EXPLOIT, "confirmer": CONFIRM,
               "rapport": REPORT, "aide": HELP, "perimetre": SCOPE}
    action = name if name in KNOWN_ACTIONS else aliases.get(name, UNKNOWN)
    if action == UNKNOWN:
        return Command(action=UNKNOWN, raw=raw)

    cmd = Command(action=action, raw=raw)
    if action in ACTIONS_NEED_INDEX:
        cmd.index = _first_int(rest)
    elif action in ACTIONS_NEED_ARG:
        cmd.arg = rest
    return cmd


def _parse_natural(text: str, raw: str) -> Command:
    norm = _strip_accents(text.lower())

    # Meilleure correspondance = mot-clé apparaissant le plus tôt ; l'ordre de
    # NL_KEYWORDS tranche les égalités (priorité déclarée).
    best: tuple[int, int, str] | None = None  # (position, priorité, action)
    for priority, (action, keywords) in enumerate(NL_KEYWORDS):
        for kw in keywords:
            pos = norm.find(_strip_accents(kw))
            if pos != -1:
                cand = (pos, priority, action)
                if best is None or cand[:2] < best[:2]:
                    best = cand
                break  # 1er mot-clé trouvé pour cette action suffit

    if best is None:
        return Command(action=UNKNOWN, raw=raw)

    action = best[2]
    cmd = Command(action=action, raw=raw)
    if action in ACTIONS_NEED_INDEX:
        cmd.index = _first_int(norm)
    elif action == SCOPE:
        # La cible = le texte débarrassé des mots d'intention et de liaison.
        # On normalise les accents d'abord (les mots-clés du filtre sont sans
        # accent, et une cible/hôte n'en porte pas) pour que « périmètre » soit
        # bien retiré.
        stripped = _SCOPE_STRIP.sub(" ", _strip_accents(text))
        cmd.arg = " ".join(stripped.split()).strip(" :,.")
    return cmd


# --- Texte d'aide (utilisé par l'action HELP) -----------------------------
HELP_TEXT = (
    "Commandes disponibles :\n"
    "  /scan            — lance une campagne de reconnaissance et de scan\n"
    "  /exploit <n>     — prouve la faille n° <n> (exploitation à la demande)\n"
    "  /confirm <n>     — confirme la faille n° <n> en démontrant son impact\n"
    "  /audit           — affiche la posture de durcissement du serveur\n"
    "  /report          — génère le rapport de la campagne\n"
    "  /scope <cible>   — demande l'extension du périmètre à <cible> (supervisé)\n"
    "  /stop            — arrête la campagne en cours\n"
    "Vous pouvez aussi écrire en langage naturel (« exploite la faille 3 »)."
)


class CommandDispatcher:
    """
    Route une commande analysée vers son handler, sous garde RoE.

    Args:
        handlers: dict action -> callable(Command) -> Any. Chaque handler porte
            l'effet réel (lancer un scan, appeler exploit(finding, mode), etc.).
        roe_check: callable(action_category, target) -> {"allowed": bool,
            "reason": str}. Par défaut : DENY (deny-by-default).
        target: cible courante, transmise au contrôle RoE.
    """

    def __init__(
        self,
        handlers: dict[str, Callable[[Command], Any]] | None = None,
        roe_check: Callable[[str, str], dict[str, Any]] | None = None,
        target: str = "",
    ):
        self.handlers = handlers or {}
        self.roe_check = roe_check or self._deny_by_default
        self.target = target

    @staticmethod
    def _deny_by_default(action_category: str, target: str) -> dict[str, Any]:
        return {
            "allowed": False,
            "reason": "Aucun périmètre RoE fourni : action refusée "
                      "(deny-by-default).",
        }

    def dispatch(self, raw: str) -> dict[str, Any]:
        """
        Analyse `raw`, valide, applique la garde RoE puis exécute le handler.

        Returns:
            {status, action, command, ...}. status ∈ {"ok", "help", "unknown",
            "needs_index", "needs_arg", "denied", "unsupported", "handler_error"}.
        """
        cmd = parse_command(raw)

        if cmd.action == UNKNOWN:
            return {"status": "unknown", "action": UNKNOWN, "command": cmd,
                    "reason": "Commande non reconnue.", "help": HELP_TEXT}

        if cmd.action == HELP:
            return {"status": "help", "action": HELP, "command": cmd,
                    "help": HELP_TEXT}

        # Validation des arguments requis
        if cmd.action in ACTIONS_NEED_INDEX and cmd.index is None:
            return {"status": "needs_index", "action": cmd.action, "command": cmd,
                    "reason": f"La commande '{cmd.action}' attend un numéro de "
                              f"faille (ex. /{cmd.action} 3)."}
        if cmd.action in ACTIONS_NEED_ARG and not cmd.arg:
            return {"status": "needs_arg", "action": cmd.action, "command": cmd,
                    "reason": f"La commande '{cmd.action}' attend un argument "
                              f"(ex. /{cmd.action} exemple.com)."}

        # Garde RoE : re-vérifiée avant toute action offensive (deny-by-default)
        roe_category = ACTION_ROE_CATEGORY.get(cmd.action)
        if roe_category:
            decision = self.roe_check(roe_category, self.target)
            if not decision.get("allowed"):
                return {"status": "denied", "action": cmd.action, "command": cmd,
                        "reason": decision.get("reason",
                                               "Action hors périmètre (RoE).")}

        handler = self.handlers.get(cmd.action)
        if handler is None:
            return {"status": "unsupported", "action": cmd.action, "command": cmd,
                    "reason": f"Aucun handler pour l'action '{cmd.action}'."}

        try:
            result = handler(cmd)
        except Exception as e:  # un handler ne doit pas casser la console
            return {"status": "handler_error", "action": cmd.action, "command": cmd,
                    "reason": f"Erreur du handler ({type(e).__name__}): {e}"}

        return {"status": "ok", "action": cmd.action, "command": cmd,
                "result": result}
