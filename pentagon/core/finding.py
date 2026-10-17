"""
Modèle « Finding » de première classe pour PENTAGON (Lot UI-2 — fondation F1).

Aujourd'hui les résultats d'un testeur vivent noyés dans le JSON de campagne.
Ce module introduit un objet **Finding** identifiable et persistant, porteur
de son propre cycle de vie de PREUVE :

    Détecté  →  Prouvé  →  Confirmé
    detected    proven     confirmed

- `detected`  : la faille est seulement CORRÉLÉE (ex. CVE rapprochée d'une
                version), sans démonstration active.
- `proven`    : un testeur l'a PROUVÉE automatiquement et de façon non
                destructive pendant la campagne (le marqueur SSTI a été
                évalué, /etc/passwd a été lu, etc.).
- `confirmed` : l'opérateur a demandé une exploitation plus poussée (à la
                demande) qui démontre l'impact réel — toujours non
                destructive et sous RoE.

Le module est volontairement PUR (aucun réseau, aucune dépendance aux
outils) : il définit la donnée et ses transitions. L'agent Exploitation
s'en sert pour router une commande d'exploitation vers le bon testeur et
faire avancer l'état du Finding (voir exploitation_agent.exploit).
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


# --- États de preuve, du plus faible au plus fort -------------------------
DETECTED = "detected"
PROVEN = "proven"
CONFIRMED = "confirmed"

PROOF_STATES = (DETECTED, PROVEN, CONFIRMED)
_RANK = {state: i for i, state in enumerate(PROOF_STATES)}


def proof_rank(state: str) -> int:
    """Rang ordinal d'un état de preuve (inconnu → -1)."""
    return _RANK.get(state, -1)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Catégories de faille → catégorie d'action RoE ------------------------
# Toutes les catégories ci-dessous relèvent de l'action RoE « exploitation »
# (deny-by-default : l'orchestrateur ne lance l'agent que si la politique
# autorise explicitement cette catégorie). Le mapping est centralisé ici
# pour que la commande d'exploitation sache quoi faire re-vérifier au RoE.
CATEGORY_TO_ROE_ACTION: dict[str, str] = {
    "auth": "exploitation",
    "jwt": "exploitation",
    "idor": "exploitation",
    "sqli": "exploitation",
    "xss": "exploitation",
    "lfi": "exploitation",
    "open_redirect": "exploitation",
    "ssti": "exploitation",
    "ssrf": "exploitation",
    "csrf": "exploitation",
}


def roe_action_for(category: str) -> str:
    """
    Catégorie d'action RoE à faire re-vérifier pour exploiter cette faille.
    Par défaut « exploitation » (le plus restrictif des actes offensifs),
    jamais « passive » : on ne relâche pas la garde sur une catégorie inconnue.
    """
    return CATEGORY_TO_ROE_ACTION.get(category, "exploitation")


@dataclass
class Finding:
    """
    Une vulnérabilité identifiable, avec son état de preuve et son historique
    d'évidence. Sérialisable (to_dict / from_dict) pour persistance disque à
    côté des campagnes, indexable par session.
    """

    session_id: str
    title: str
    category: str
    severity: str = "info"
    owasp: str = ""
    cwe: str = ""
    affected_endpoint: str = ""
    param: str = ""
    payload: str = ""
    confidence: float = 0.0
    proof_state: str = DETECTED
    evidence: list[dict[str, Any]] = field(default_factory=list)
    id: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = uuid.uuid4().hex[:12]
        now = _now_iso()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
        if self.proof_state not in PROOF_STATES:
            self.proof_state = DETECTED

    # --- Transitions d'état (monotones : jamais de régression) ------------
    def promote(self, new_state: str) -> bool:
        """
        Fait avancer l'état de preuve vers `new_state` SANS jamais régresser.

        Returns:
            True si l'état a effectivement avancé, False sinon (état inconnu,
            égal ou inférieur — on ne rétrograde jamais un Finding déjà prouvé).
        """
        if new_state not in PROOF_STATES:
            return False
        if proof_rank(new_state) <= proof_rank(self.proof_state):
            return False
        self.proof_state = new_state
        self.updated_at = _now_iso()
        return True

    def add_evidence(
        self,
        stage: str,
        tool: str,
        snippet: str,
        at: str | None = None,
    ) -> dict[str, Any]:
        """
        Ajoute une entrée d'évidence horodatée et met à jour `updated_at`.

        `stage` situe l'évidence dans le cycle (« detect », « prove »,
        « confirm »). `snippet` est une trace NON SENSIBLE (jamais un
        identifiant, mot de passe ou token brut).
        """
        entry = {
            "stage": stage,
            "tool": tool,
            "snippet": snippet,
            "at": at or _now_iso(),
        }
        self.evidence.append(entry)
        self.updated_at = entry["at"]
        return entry

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Reconstruit un Finding depuis sa forme sérialisée (champs inconnus ignorés)."""
        known = {f for f in cls.__dataclass_fields__}  # noqa: SLF001
        return cls(**{k: v for k, v in data.items() if k in known})


def make_finding(
    session_id: str,
    category: str,
    raw: dict[str, Any],
    *,
    proof_state: str = PROVEN,
    tool: str = "",
) -> Finding:
    """
    Construit un Finding à partir d'un finding BRUT renvoyé par un testeur
    (contrat standard : title, severity, affected_endpoint, param, payload,
    evidence, owasp, cwe, confidence).

    `proof_state` par défaut : `proven` — ce que les testeurs prouvent déjà
    en passage automatique. Passer `detected` pour ce qui n'est que corrélé
    (ex. rapprochement CVE).
    """
    finding = Finding(
        session_id=session_id,
        title=str(raw.get("title") or category),
        category=category,
        severity=str(raw.get("severity") or "info"),
        owasp=str(raw.get("owasp") or ""),
        cwe=str(raw.get("cwe") or ""),
        affected_endpoint=str(raw.get("affected_endpoint") or ""),
        param=str(raw.get("param") or ""),
        payload=str(raw.get("payload") or ""),
        confidence=float(raw.get("confidence") or 0.0),
        proof_state=proof_state,
    )
    # L'évidence brute du testeur devient la première entrée d'historique.
    raw_evidence = raw.get("evidence")
    if raw_evidence:
        stage = "prove" if proof_state == PROVEN else "detect"
        finding.add_evidence(stage=stage, tool=tool or category,
                             snippet=str(raw_evidence))
    return finding


def findings_from_result(
    session_id: str,
    category: str,
    result: dict[str, Any] | None,
    *,
    tool: str = "",
    proof_state: str = PROVEN,
) -> list[Finding]:
    """
    Dérive une liste de Finding depuis le résultat complet d'un testeur
    (contrat standard : clé `findings` = liste de findings bruts).

    Un résultat vide, en erreur ou sans `findings` donne une liste vide.
    """
    if not result:
        return []
    raws = result.get("findings") or []
    return [
        make_finding(session_id, category, raw, proof_state=proof_state, tool=tool)
        for raw in raws
        if isinstance(raw, dict)
    ]
