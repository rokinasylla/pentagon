"""
État partagé de PENTAGON (PentagonState).

Cet objet circule entre les agents au cours d'une campagne et accumule
les informations collectées. Il constitue la mémoire de travail commune
du système, permettant aux agents en aval d'exploiter les découvertes
des agents en amont.

Dans cette version (v1), l'état est un dataclass simple géré par un
orchestrateur séquentiel. Il sera migré vers un TypedDict LangGraph
avec checkpointing dans une version ultérieure.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


@dataclass
class PentagonState:
    """
    État partagé d'une campagne de pentest PENTAGON.
    
    Cet objet est créé au démarrage d'une campagne, enrichi par chaque
    agent successivement, et consolidé en fin de campagne pour le rapport.
    """
    
    # === Identité de la campagne ===
    campaign_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ended_at: str | None = None
    
    # === Résultats par agent ===
    # Chaque agent dépose son résultat complet ici
    osint_result: dict[str, Any] | None = None
    scanning_result: dict[str, Any] | None = None
    
    # === Contexte consolidé (extrait des résultats pour usage inter-agents) ===
    # Ces champs sont remplis par l'orchestrateur à partir des résultats bruts
    # pour faciliter l'accès des agents en aval.
    discovered_infrastructure: dict[str, Any] = field(default_factory=dict)
    
    # === Trace d'exécution ===
    agents_executed: list[str] = field(default_factory=list)
    execution_log: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    
    def log_event(self, agent: str, event: str, details: str = "") -> None:
        """Enregistre un événement dans le journal d'exécution."""
        self.execution_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": agent,
            "event": event,
            "details": details,
        })
    
    def log_error(self, agent: str, error: str) -> None:
        """Enregistre une erreur dans l'état."""
        self.errors.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": agent,
            "error": error,
        })
    
    def update_infrastructure(self, key: str, value: Any) -> None:
        """Met à jour le contexte d'infrastructure partagé."""
        self.discovered_infrastructure[key] = value
    
    def to_dict(self) -> dict[str, Any]:
        """Sérialise l'état complet en dictionnaire (pour sauvegarde JSON)."""
        return {
            "campaign_id": self.campaign_id,
            "target": self.target,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "agents_executed": self.agents_executed,
            "discovered_infrastructure": self.discovered_infrastructure,
            "osint_result": self.osint_result,
            "scanning_result": self.scanning_result,
            "execution_log": self.execution_log,
            "errors": self.errors,
        }
