"""
Routage de modele par role pour PENTAGON (Lot L1 de la spec agent-autonome).

Ce module decide QUEL fournisseur et QUEL modele LLM utiliser selon le role
de l'agent appelant (orchestrator, planner, osint, scanning, web_app,
exploitation, reporting, assistant). Il lit `pentagon/config/models.json`.

Il ne depend que de la bibliotheque standard : aucune cle API ni SDK n'est
requis pour l'importer ou le tester. Le `LLMClient` s'appuie dessus pour
construire le bon client reseau, mais toute la logique de selection vit ici
et reste testable hors-ligne.

Principes :
  * Fermeture gracieuse : un role inconnu, un fichier absent ou mal forme
    retombe sur le fournisseur/modele par defaut, jamais une exception opaque.
  * La config est la source de verite ; une cible explicite cote appelant
    (LLMClient(model=...)) prime toujours (gere dans LLMClient, pas ici).
  * Le plafond de jetons par campagne (BudgetTracker) est optionnel et
    partageable entre agents d'une meme campagne.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Chemin par defaut : pentagon/config/models.json (relatif a ce fichier).
_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "models.json"

# Repli de derniere instance si le fichier de config est introuvable/illisible.
_HARD_DEFAULTS = {
    "default_provider": "deepseek",
    "default_model": "deepseek-chat",
    "default_params": {"temperature": 0.3, "max_tokens": 2000},
    "providers": {
        "deepseek": {
            "base_url": "https://api.deepseek.com",
            "api_key_env": "DEEPSEEK_API_KEY",
        }
    },
}


@dataclass(frozen=True)
class ModelRoute:
    """Resolution complete pour un role : de quoi construire un client LLM."""

    role: str
    provider: str
    model: str
    base_url: str
    api_key_env: str
    temperature: float
    max_tokens: int


class BudgetExceededError(RuntimeError):
    """Levee quand une campagne depasse son plafond de jetons."""


class BudgetTracker:
    """
    Suivi du budget de jetons d'une campagne (SS15.1).

    Partageable entre plusieurs agents : on passe la meme instance a chaque
    LLMClient d'une campagne. `max_tokens <= 0` (ou None) desactive le plafond.
    """

    def __init__(self, max_tokens: Optional[int] = None, warn_ratio: float = 0.8):
        self.max_tokens = int(max_tokens or 0)
        self.warn_ratio = float(warn_ratio)
        self.used_tokens = 0
        self._warned = False

    @property
    def enabled(self) -> bool:
        return self.max_tokens > 0

    @property
    def remaining(self) -> Optional[int]:
        """Jetons restants, ou None si aucun plafond n'est fixe."""
        if not self.enabled:
            return None
        return max(0, self.max_tokens - self.used_tokens)

    @property
    def is_warning(self) -> bool:
        """True si la consommation a franchi le seuil d'avertissement."""
        if not self.enabled:
            return False
        return self.used_tokens >= self.max_tokens * self.warn_ratio

    def check(self) -> None:
        """
        A appeler AVANT un appel LLM. Leve BudgetExceededError si le plafond
        est deja atteint, pour empecher un appel supplementaire.
        """
        if self.enabled and self.used_tokens >= self.max_tokens:
            raise BudgetExceededError(
                f"Plafond de jetons de campagne atteint "
                f"({self.used_tokens}/{self.max_tokens})."
            )

    def add(self, tokens: int) -> bool:
        """
        Enregistre la consommation d'un appel. Renvoie True si cet ajout fait
        franchir le seuil d'avertissement pour la premiere fois (utile pour
        n'avertir qu'une seule fois).
        """
        self.used_tokens += max(0, int(tokens or 0))
        if self.enabled and self.is_warning and not self._warned:
            self._warned = True
            return True
        return False


class ModelRouter:
    """
    Lit `models.json` et resout le fournisseur/modele/parametres par role.
    """

    def __init__(self, config_path: Optional[str | Path] = None):
        self.config_path = Path(config_path) if config_path else _DEFAULT_CONFIG_PATH
        self._config: dict = {}
        self.reload()

    def reload(self) -> None:
        """Relit le fichier de config (tolere l'absence/les erreurs de parsing)."""
        try:
            with open(self.config_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # JSON valide mais pas un objet (ex. une chaine ou une liste) :
            # inutilisable comme config -> repli sur les defauts durs.
            self._config = data if isinstance(data, dict) else dict(_HARD_DEFAULTS)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            self._config = dict(_HARD_DEFAULTS)

    # --- accesseurs de bas niveau -----------------------------------------

    def _default_provider(self) -> str:
        return self._config.get("default_provider", _HARD_DEFAULTS["default_provider"])

    def _default_model(self) -> str:
        return self._config.get("default_model", _HARD_DEFAULTS["default_model"])

    def _default_params(self) -> dict:
        params = dict(_HARD_DEFAULTS["default_params"])
        params.update(self._config.get("default_params", {}))
        return params

    def provider(self, name: str) -> dict:
        """Config d'un fournisseur (base_url, api_key_env). Repli sur defauts."""
        providers = self._config.get("providers", {})
        if name in providers:
            return providers[name]
        if name in _HARD_DEFAULTS["providers"]:
            return _HARD_DEFAULTS["providers"][name]
        # Fournisseur inconnu : on retombe sur le fournisseur par defaut connu.
        return providers.get(
            self._default_provider(),
            _HARD_DEFAULTS["providers"]["deepseek"],
        )

    def budget_config(self) -> dict:
        return self._config.get("budget", {})

    def new_budget_tracker(self) -> BudgetTracker:
        """Fabrique un BudgetTracker a partir de la section 'budget' de la config."""
        b = self.budget_config()
        return BudgetTracker(
            max_tokens=b.get("per_campaign_max_tokens", 0),
            warn_ratio=b.get("warn_ratio", 0.8),
        )

    # --- resolution principale --------------------------------------------

    def resolve(self, role: Optional[str] = None) -> ModelRoute:
        """
        Resout un role en une ModelRoute complete.

        Un role None ou inconnu retombe proprement sur le fournisseur/modele
        et les parametres par defaut.
        """
        roles = self._config.get("roles", {})
        role_cfg = roles.get(role, {}) if role else {}

        default_params = self._default_params()
        provider_name = role_cfg.get("provider", self._default_provider())
        model = role_cfg.get("model", self._default_model())
        temperature = role_cfg.get("temperature", default_params["temperature"])
        max_tokens = role_cfg.get("max_tokens", default_params["max_tokens"])

        prov = self.provider(provider_name)

        return ModelRoute(
            role=role or "(defaut)",
            provider=provider_name,
            model=model,
            base_url=prov.get("base_url", _HARD_DEFAULTS["providers"]["deepseek"]["base_url"]),
            api_key_env=prov.get("api_key_env", _HARD_DEFAULTS["providers"]["deepseek"]["api_key_env"]),
            temperature=float(temperature),
            max_tokens=int(max_tokens),
        )
