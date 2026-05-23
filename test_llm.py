"""
Test rapide du client LLM DeepSeek.

Exécution : python test_llm.py
"""

from pentagon.core.llm_client import LLMClient


def main():
    print("=" * 60)
    print("PENTAGON — Test du client LLM DeepSeek")
    print("=" * 60)
    
    # 1. Initialise le client
    print("\n[1/3] Initialisation du client LLM...")
    try:
        llm = LLMClient()
        print(f"      ✓ Client initialisé")
        print(f"      ✓ Modèle : {llm.model}")
        print(f"      ✓ Base URL : {llm.base_url}")
    except ValueError as e:
        print(f"      ✗ Erreur : {e}")
        return
    
    # 2. Health check
    print("\n[2/3] Vérification de la connectivité (health check)...")
    if llm.health_check():
        print("      ✓ Le LLM répond correctement")
    else:
        print("      ✗ Le LLM ne répond pas")
        return
    
    # 3. Test conversationnel simple
    print("\n[3/3] Test conversationnel — l'agent se présente...")
    response = llm.chat(
        system_prompt=(
            "Tu es l'Agent OSINT de PENTAGON, un système multi-agent "
            "de test d'intrusion automatisé. Présente-toi en 2 phrases courtes, "
            "en mentionnant ton rôle dans la phase 2 du PTES (Intelligence Gathering)."
        ),
        user_prompt="Présente-toi.",
        max_tokens=200,
    )
    print(f"\nRéponse de l'agent :\n")
    print(f"   {response}")
    
    print("\n" + "=" * 60)
    print("✓ Test réussi ! Le LLM est opérationnel.")
    print("=" * 60)


if __name__ == "__main__":
    main()
