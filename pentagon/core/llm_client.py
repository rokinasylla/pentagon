"""
Client LLM pour PENTAGON.

Ce module fournit une abstraction sur le fournisseur LLM utilisé (DeepSeek).
L'utilisation d'une interface unique permet de changer de fournisseur LLM
sans modifier le code des agents (principe de découplage).
"""

import os
from typing import Optional
from openai import OpenAI
from dotenv import load_dotenv

# Charge les variables d'environnement depuis .env
load_dotenv()


class LLMClient:
    """
    Client LLM unifié pour PENTAGON.
    
    Utilise le SDK OpenAI qui est compatible avec l'API DeepSeek
    (DeepSeek expose une API compatible OpenAI).
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """
        Initialise le client LLM.
        
        Args:
            api_key: clé API DeepSeek. Si None, lue depuis DEEPSEEK_API_KEY.
            base_url: URL de l'API. Si None, lue depuis DEEPSEEK_BASE_URL.
            model: nom du modèle. Si None, lu depuis DEEPSEEK_MODEL.
        """
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        self.base_url = base_url or os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        self.model = model or os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
        
        if not self.api_key:
            raise ValueError(
                "Clé API DeepSeek manquante. "
                "Définissez DEEPSEEK_API_KEY dans le fichier .env"
            )
        
        # Initialise le client OpenAI configuré pour DeepSeek
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
        )
    
    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> str:
        """
        Envoie une requête de chat au LLM et retourne la réponse texte.
        
        Args:
            system_prompt: instructions de système (rôle, contexte, persona).
            user_prompt: question ou tâche à effectuer.
            temperature: niveau de créativité (0.0 = déterministe, 1.0 = créatif).
                         Pour le pentest, on utilise 0.3 pour avoir des réponses
                         plutôt déterministes mais avec un peu de souplesse.
            max_tokens: longueur maximale de la réponse.
        
        Returns:
            La réponse texte du LLM.
        """
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        
        return response.choices[0].message.content
    
    def health_check(self) -> bool:
        """
        Vérifie que le LLM est joignable et fonctionnel.
        
        Returns:
            True si le LLM répond correctement, False sinon.
        """
        try:
            response = self.chat(
                system_prompt="Tu es un assistant qui répond très brièvement.",
                user_prompt="Réponds uniquement par OK si tu me reçois.",
                max_tokens=10,
            )
            return "OK" in response.upper()
        except Exception as e:
            print(f"[health_check] Erreur: {e}")
            return False
