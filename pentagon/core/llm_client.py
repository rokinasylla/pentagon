"""
Client LLM pour PENTAGON.

Ce module fournit une abstraction sur le fournisseur LLM utilise. L'utilisation
d'une interface unique permet de changer de fournisseur/modele sans modifier le
code des agents (principe de decouplage).

Routage par role (Lot L1 de la spec agent-autonome, SS15.1)
-----------------------------------------------------------
Le client peut router automatiquement vers le bon fournisseur et le bon modele
selon le ROLE de l'agent appelant, en s'appuyant sur `ModelRouter`
(pentagon/core/model_router.py), qui lit `pentagon/config/models.json`.

    LLMClient()                      # fournisseur/modele par defaut (deepseek-chat)
    LLMClient(role="planner")        # modele de raisonnement route pour le planner
    LLMClient(model="deepseek-chat") # cible explicite : prime sur le routage

Precedence de resolution :
  * model      : argument explicite  >  variable DEEPSEEK_MODEL  >  route du role
  * base_url   : argument explicite  >  DEEPSEEK_BASE_URL (si fournisseur deepseek)
                                                            >  route du role
  * cle API    : argument explicite  >  variable d'env nommee par le fournisseur
                 (DEEPSEEK_API_KEY par defaut, ANTHROPIC_API_KEY pour Anthropic)

Compatibilite : tous les fournisseurs route exposent une API compatible SDK
OpenAI (DeepSeek nativement ; Anthropic via son endpoint compatible OpenAI),
donc un seul code client suffit.
"""

import os
from typing import Optional

from dotenv import load_dotenv

from pentagon.core.model_router import BudgetTracker, ModelRouter

# Charge les variables d'environnement depuis .env
load_dotenv()


class LLMClient:
    """
    Client LLM unifie pour PENTAGON.

    Utilise le SDK OpenAI, compatible avec DeepSeek (nativement) et avec
    l'endpoint compatible OpenAI d'Anthropic.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        role: Optional[str] = None,
        router: Optional[ModelRouter] = None,
        budget: Optional[BudgetTracker] = None,
    ):
        """
        Initialise le client LLM.

        Args:
            api_key: cle API. Si None, lue depuis la variable d'env du fournisseur.
            base_url: URL de l'API. Si None, deduite du routage (ou DEEPSEEK_BASE_URL).
            model: nom du modele. Si fourni, prime sur le routage par role.
            role: role de l'agent appelant (orchestrator, planner, osint,
                  scanning, web_app, exploitation, reporting, assistant). Determine
                  le fournisseur/modele/parametres par defaut via le ModelRouter.
            router: ModelRouter a utiliser (une instance partagee est creee sinon).
            budget: BudgetTracker optionnel, partage entre agents d'une campagne
                    pour appliquer un plafond de jetons.
        """
        self.router = router or ModelRouter()
        self.budget = budget
        self.role = role

        # Resolution du fournisseur/modele/parametres pour ce role.
        route = self.router.resolve(role)
        self.route = route

        # Modele : explicite > DEEPSEEK_MODEL (echappatoire mono-modele) > route.
        self.model = model or os.getenv("DEEPSEEK_MODEL") or route.model

        # base_url : explicite > DEEPSEEK_BASE_URL (si deepseek) > route.
        if base_url:
            self.base_url = base_url
        elif route.api_key_env == "DEEPSEEK_API_KEY":
            self.base_url = os.getenv("DEEPSEEK_BASE_URL", route.base_url)
        else:
            self.base_url = route.base_url

        # Parametres par defaut issus du routage (appliques si l'appelant ne
        # precise rien lors de l'appel chat()).
        self.default_temperature = route.temperature
        self.default_max_tokens = route.max_tokens

        # Cle API : explicite > variable d'env du fournisseur.
        self.api_key_env = route.api_key_env
        self.api_key = api_key or os.getenv(route.api_key_env)
        if not self.api_key:
            raise ValueError(
                f"Cle API manquante pour le fournisseur '{route.provider}'. "
                f"Definissez {route.api_key_env} dans le fichier .env"
            )

        # Import paresseux : le module reste importable sans le SDK openai
        # (utile pour les tests de routage hors-ligne).
        from openai import OpenAI

        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    # --- suivi de budget ---------------------------------------------------

    def _before_call(self) -> None:
        if self.budget is not None:
            self.budget.check()

    def _record_usage(self, response) -> None:
        if self.budget is None:
            return
        usage = getattr(response, "usage", None)
        total = getattr(usage, "total_tokens", 0) if usage else 0
        warned = self.budget.add(total or 0)
        if warned:
            print(
                f"[budget] Seuil d'avertissement franchi : "
                f"{self.budget.used_tokens}/{self.budget.max_tokens} jetons."
            )

    # --- appels -----------------------------------------------------------

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
    ) -> str:
        """
        Envoie une requete de chat au LLM et retourne la reponse texte.

        Args:
            system_prompt: instructions de systeme (role, contexte, persona).
            user_prompt: question ou tache a effectuer.
            temperature: niveau de creativite. Si None, valeur par defaut du role.
            max_tokens: longueur maximale de la reponse. Si None, defaut du role.
            json_mode: si True, force une reponse JSON valide. Le prompt doit
                       mentionner « JSON » (contrainte DeepSeek/OpenAI).

        Returns:
            La reponse texte du LLM.
        """
        self._before_call()
        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.default_temperature if temperature is None else temperature,
            "max_tokens": self.default_max_tokens if max_tokens is None else max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        response = self.client.chat.completions.create(**kwargs)
        self._record_usage(response)

        return response.choices[0].message.content

    def chat_messages(
        self,
        messages: list[dict],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        Variante multi-tours : envoie une liste de messages complete et renvoie
        la reponse texte. Utilisee par l'assistant conversationnel (console web),
        ou l'historique de la discussion doit etre conserve d'un tour a l'autre.

        Args:
            messages: liste [{"role": "system|user|assistant", "content": "..."}].
            temperature: niveau de creativite. Si None, valeur par defaut du role.
            max_tokens: longueur maximale de la reponse. Si None, defaut du role.

        Returns:
            La reponse texte du LLM.
        """
        self._before_call()
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.default_temperature if temperature is None else temperature,
            max_tokens=self.default_max_tokens if max_tokens is None else max_tokens,
        )
        self._record_usage(response)
        return response.choices[0].message.content

    def health_check(self) -> bool:
        """
        Verifie que le LLM est joignable et fonctionnel.

        Returns:
            True si le LLM repond correctement, False sinon.
        """
        try:
            response = self.chat(
                system_prompt="Tu es un assistant qui repond tres brievement.",
                user_prompt="Reponds uniquement par OK si tu me recois.",
                max_tokens=10,
            )
            return "OK" in response.upper()
        except Exception as e:
            print(f"[health_check] Erreur: {e}")
            return False
