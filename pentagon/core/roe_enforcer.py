"""
RoE Enforcer (Rules of Engagement) pour PENTAGON.

Ce module est le garde-fou de gouvernance de PENTAGON. Il garantit que
toutes les actions des agents restent dans le perimetre legalement et
ethiquement autorise, defini par une politique RoE.

Principe de securite : DENY BY DEFAULT.
Toute cible ou action non explicitement autorisee est refusee.

Fonctions :
- Validation des cibles (la cible est-elle dans le perimetre autorise ?)
- Validation des categories d'action (l'action est-elle permise ?)
- Tracabilite (toutes les decisions sont journalisees pour l'audit)

Reference architecturale : Principe P6 (Human-in-the-Loop / RoE Enforcement)
Standards : PTES Pre-engagement, normes ethiques du pentest legal.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# Categories d'action, par niveau de risque croissant
ACTION_CATEGORIES = {
    "passive": "Reconnaissance passive (WHOIS, DNS, analyse de bundle JS)",
    "active_scan": "Scan actif (Nmap, sondage d'endpoints, headers)",
    "exploitation": "Tests offensifs (injection SQL, XSS, bypass d'auth)",
    "destructive": "Actions destructives (DoS, suppression de donnees)",
}


class RoEViolation(Exception):
    """Levee quand une action viole les regles d'engagement."""
    pass


class RoEEnforcer:
    """
    Garde-fou de gouvernance de PENTAGON.

    Valide les cibles et les actions contre une politique RoE,
    avec journalisation complete pour l'audit.
    """

    def __init__(self, policy_path: str | None = None):
        """
        Initialise le RoE Enforcer avec une politique.

        Args:
            policy_path: chemin du fichier de politique JSON.
                         Si None, utilise la politique par defaut.
        """
        if policy_path is None:
            policy_path = str(Path(__file__).parent.parent / "config" / "roe_policy.json")

        self.policy_path = policy_path
        self.policy = self._load_policy(policy_path)
        self.decision_log: list[dict[str, Any]] = []

    def _load_policy(self, path: str) -> dict[str, Any]:
        """Charge la politique RoE depuis le fichier JSON."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            raise RoEViolation(
                f"Politique RoE introuvable : {path}. "
                "Impossible de demarrer sans perimetre defini (deny by default)."
            )
        except json.JSONDecodeError as e:
            raise RoEViolation(f"Politique RoE malformee : {e}")

    def check_target(self, target: str) -> dict[str, Any]:
        """
        Verifie si une cible est dans le perimetre autorise.

        Args:
            target: domaine, URL ou hote a verifier.

        Returns:
            Dict avec 'allowed' (bool) et 'reason' (str).
        """
        normalized = self._normalize_target(target)
        authorized = self.policy.get("authorized_targets", [])

        is_allowed = False
        matched = None
        for auth_target in authorized:
            auth_normalized = self._normalize_target(auth_target)
            if normalized == auth_normalized:
                is_allowed = True
                matched = auth_target
                break

        if is_allowed:
            decision = {
                "allowed": True,
                "target": target,
                "normalized": normalized,
                "reason": f"Cible autorisee explicitement (correspond a '{matched}')",
            }
        else:
            decision = {
                "allowed": False,
                "target": target,
                "normalized": normalized,
                "reason": f"Cible non autorisee. Perimetre : {authorized}. "
                          f"Comportement deny-by-default applique.",
            }

        self._log_decision("check_target", decision)
        return decision

    def check_action(self, action_category: str, target: str = "") -> dict[str, Any]:
        """
        Verifie si une categorie d'action est autorisee.

        Args:
            action_category: categorie d'action ("passive", "active_scan",
                             "exploitation", "destructive").
            target: cible concernee (optionnel, pour le log).

        Returns:
            Dict avec 'allowed' (bool) et 'reason' (str).
        """
        authorized_categories = self.policy.get("authorized_action_categories", [])

        if action_category not in ACTION_CATEGORIES:
            decision = {
                "allowed": False,
                "action_category": action_category,
                "target": target,
                "reason": f"Categorie d'action inconnue : '{action_category}'",
            }
            self._log_decision("check_action", decision)
            return decision

        is_allowed = action_category in authorized_categories

        if is_allowed:
            decision = {
                "allowed": True,
                "action_category": action_category,
                "target": target,
                "reason": f"Action '{action_category}' autorisee par la politique",
            }
        else:
            decision = {
                "allowed": False,
                "action_category": action_category,
                "target": target,
                "reason": f"Action '{action_category}' NON autorisee. "
                          f"Categories permises : {authorized_categories}",
            }

        self._log_decision("check_action", decision)
        return decision

    def enforce(self, target: str, action_category: str) -> None:
        """
        Valide cible ET action ensemble, et leve une exception si refuse.

        C'est la methode a appeler avant toute action d'agent.

        Args:
            target: cible de l'action.
            action_category: categorie de l'action.

        Raises:
            RoEViolation: si la cible ou l'action n'est pas autorisee.
        """
        target_decision = self.check_target(target)
        if not target_decision["allowed"]:
            raise RoEViolation(f"CIBLE REFUSEE : {target_decision['reason']}")

        action_decision = self.check_action(action_category, target)
        if not action_decision["allowed"]:
            raise RoEViolation(f"ACTION REFUSEE : {action_decision['reason']}")

    def add_authorized_target(self, target: str, justification: str = "") -> bool:
        """
        Étend dynamiquement le périmètre en ajoutant une cible autorisée.

        Utilisée par le mode "interactive-scope" : quand l'opérateur décide,
        EN COURS de campagne, d'autoriser un asset découvert (ex: une IP
        trouvée par l'OSINT). Reste fidèle au deny-by-default — rien n'est
        ajouté sans cet appel explicite — et journalise la décision pour
        l'audit.

        NB de gouvernance : autoriser un asset ici n'engage QUE la
        responsabilité de l'opérateur. La légalité du test dépend de l'accord
        réel du propriétaire (pré-engagement), pas de cet ajout technique.

        Args:
            target: l'asset à autoriser (domaine, hôte ou IP).
            justification: motif fourni par l'opérateur (tracé dans l'audit).

        Returns:
            True si la cible a été ajoutée, False si elle était déjà autorisée.
        """
        normalized = self._normalize_target(target)
        existing = {
            self._normalize_target(t)
            for t in self.policy.get("authorized_targets", [])
        }

        if normalized in existing:
            self._log_decision("scope_expansion", {
                "allowed": True,
                "target": target,
                "normalized": normalized,
                "reason": "Déjà dans le périmètre autorisé (aucun changement).",
            })
            return False

        self.policy.setdefault("authorized_targets", []).append(target)
        self._log_decision("scope_expansion", {
            "allowed": True,
            "target": target,
            "normalized": normalized,
            "reason": f"Périmètre étendu par l'opérateur. Justification : "
                      f"{justification or '(non précisée)'}",
        })
        return True

    @classmethod
    def from_user_input(
        cls,
        authorized_targets: list[str],
        authorized_actions: list[str],
        operator_name: str = "anonyme",
    ) -> "RoEEnforcer":
        """
        Cree un RoE Enforcer a partir d'une saisie utilisateur (interface).

        Permet a un operateur de definir son perimetre sans editer de fichier,
        en respectant le principe de separation utilisateur / code.

        Args:
            authorized_targets: liste des cibles autorisees par l'operateur.
            authorized_actions: liste des categories d'action autorisees.
            operator_name: nom de l'operateur (pour la tracabilite/audit).

        Returns:
            Une instance de RoEEnforcer configuree avec cette politique.
        """
        policy = {
            "policy_name": f"Politique RoE — mission de {operator_name}",
            "version": "1.0",
            "description": "Politique generee dynamiquement via l'interface operateur.",
            "default_behavior": "deny",
            "authorized_targets": authorized_targets,
            "authorized_action_categories": authorized_actions,
            "operator": operator_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "notes": "deny by default : toute cible/action non listee est refusee.",
        }

        instance = cls.__new__(cls)
        instance.policy_path = "<dynamique>"
        instance.policy = policy
        instance.decision_log = []

        return instance

    def _normalize_target(self, target: str) -> str:
        """
        Normalise une cible pour comparaison (extrait le domaine/hote).

        "https://exemple.com/path" -> "exemple.com"
        "exemple.com" -> "exemple.com"
        """
        target = target.strip().lower()

        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            return parsed.netloc

        return target.split("/")[0]

    def _log_decision(self, check_type: str, decision: dict[str, Any]) -> None:
        """Journalise une decision RoE pour l'audit."""
        self.decision_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "check_type": check_type,
            "decision": decision,
        })

    def get_audit_log(self) -> list[dict[str, Any]]:
        """Retourne le journal complet des decisions (pour l'audit)."""
        return self.decision_log

    def print_summary(self) -> None:
        """Affiche un resume des decisions prises."""
        allowed = sum(1 for d in self.decision_log if d["decision"].get("allowed"))
        denied = len(self.decision_log) - allowed
        print(f"[RoE] Decisions : {allowed} autorisees, {denied} refusees")
