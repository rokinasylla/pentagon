"""
Test de l'Agent OSINT minimal de PENTAGON.

Exécution : python test_osint_agent.py
"""

import json
import os
from datetime import datetime, timezone
from pentagon.agents.osint_agent import OSINTAgent


def main():
    print("=" * 70)
    print("PENTAGON — Agent OSINT")
    print("=" * 70)
    
    # Cible : TechShop (application vulnérable du mémoire)
    target = "techshop-vuln.rokina-sylla.me"
    
    # Initialise l'agent
    agent = OSINTAgent()
    
    # Lance l'agent
    result = agent.run(target)
    
    # Sauvegarde le résultat complet en JSON (pour les agents en aval et l'audit)
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_file = f"results/osint_{target}_{timestamp}.json"
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)
    
    # Affiche le résumé exécutif (lisible pour humain)
    print("\n" + "=" * 70)
    print("RÉSUMÉ EXÉCUTIF — pour lecture humaine")
    print("=" * 70 + "\n")
    print(result.get("executive_summary", "Aucun résumé disponible."))
    
    # Indique où trouver le détail complet
    print("\n" + "=" * 70)
    print("📊 STATISTIQUES")
    print("=" * 70)
    print(f"  Cible            : {result['target']}")
    print(f"  Phase PTES       : {result['ptes_phase']} (Intelligence Gathering)")
    print(f"  Tactique ATT&CK  : {result['attack_tactic']}")
    print(f"  Durée            : {result['duration_seconds']:.2f}s")
    print(f"  Outils utilisés  : {', '.join(result['tools_used'])}")
    print(f"  Findings         : {len(result['analysis'].get('key_findings', []))}")
    print(f"  Confiance LLM    : {result['analysis'].get('confidence', 'N/A')}")
    print(f"\n  📂 Rapport JSON complet : {output_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
