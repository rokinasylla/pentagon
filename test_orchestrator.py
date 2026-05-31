"""
Test de l'orchestrateur PENTAGON (chaîne OSINT → Scanning).

Exécution : python test_orchestrator.py
"""

from pentagon.core.orchestrator import Orchestrator


def main():
    target = "techshop-vuln.rokina-sylla.me"
    
    # Initialise l'orchestrateur
    orchestrator = Orchestrator()
    
    # Lance la campagne complète
    state = orchestrator.run_campaign(
        target=target,
        scan_profile="web_focused",
    )
    
    # Sauvegarde l'état consolidé
    output_file = orchestrator.save_campaign(state)
    
    # Affiche la synthèse
    print("\n" + "=" * 70)
    print("SYNTHÈSE DE LA CAMPAGNE")
    print("=" * 70)
    print(f"  Campaign ID      : {state.campaign_id}")
    print(f"  Cible            : {state.target}")
    print(f"  Agents exécutés  : {', '.join(state.agents_executed)}")
    print(f"  Erreurs          : {len(state.errors)}")
    
    print(f"\n  🏗️  INFRASTRUCTURE PARTAGÉE (découverte par OSINT, transmise à Scanning) :")
    for key, value in state.discovered_infrastructure.items():
        if key != "osint_summary":  # on n'affiche pas le résumé complet ici
            print(f"     • {key} : {value}")
    
    # Affiche les résumés exécutifs des deux agents
    if state.osint_result:
        print(f"\n{'─' * 70}")
        print("RÉSUMÉ OSINT")
        print(f"{'─' * 70}")
        print(state.osint_result.get("executive_summary", "N/A"))
    
    if state.scanning_result:
        print(f"\n{'─' * 70}")
        print("RÉSUMÉ SCANNING")
        print(f"{'─' * 70}")
        print(state.scanning_result.get("executive_summary", "N/A"))
    
    print(f"\n  📂 Campagne complète sauvegardée : {output_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
