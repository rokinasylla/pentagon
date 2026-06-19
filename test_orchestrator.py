"""
Test de l'orchestrateur PENTAGON (chaîne OSINT → Scanning).

Exécution : python test_orchestrator.py
"""

from pentagon.core.orchestrator import Orchestrator
from pentagon.core.roe_enforcer import RoEEnforcer


def main():
    target = "techshop-vuln.rokina-sylla.me"

    # Politique RoE de la mission : on AUTORISE explicitement l'exploitation
    # (par défaut, roe_policy.json ne permet que passive + active_scan, donc la
    # phase Exploitation serait sautée — c'est la démonstration deny-by-default).
    roe = RoEEnforcer.from_user_input(
        authorized_targets=[target, "techshop-backend-cc1t.onrender.com"],
        authorized_actions=["passive", "active_scan", "exploitation"],
        operator_name="pentest_demo",
    )

    # Initialise l'orchestrateur avec cette politique
    orchestrator = Orchestrator(roe_enforcer=roe)
    
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

    if state.web_app_result:
        print(f"\n{'─' * 70}")
        print("RÉSUMÉ WEB APP")
        print(f"{'─' * 70}")
        print(state.web_app_result.get("executive_summary", "N/A"))
        
        # Compte les vulnérabilités par sévérité
        vulns = state.web_app_result.get("analysis", {}).get("vulnerabilities", [])
        if vulns:
            from collections import Counter
            severity_counts = Counter(v.get("severity", "info") for v in vulns)
            print(f"\n  📊 Vulnérabilités : {dict(severity_counts)}")
            print(f"  ⚠️  Risque global : {state.web_app_result.get('analysis', {}).get('overall_risk', 'N/A')}")

    if state.exploitation_result:
        print(f"\n{'─' * 70}")
        print("RÉSUMÉ EXPLOITATION")
        print(f"{'─' * 70}")
        print(state.exploitation_result.get("executive_summary", "N/A"))

        exploited = state.exploitation_result.get("analysis", {}).get("exploited_vulnerabilities", [])
        if exploited:
            from collections import Counter
            sev = Counter(v.get("severity", "info") for v in exploited)
            print(f"\n  💥 Vulnérabilités PROUVÉES par exploitation : {dict(sev)}")
            print(f"  ⚠️  Risque global : {state.exploitation_result.get('analysis', {}).get('overall_risk', 'N/A')}")

    print(f"\n  📂 Campagne complète sauvegardée : {output_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
