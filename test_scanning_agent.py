"""
Test de l'Agent Scanning de PENTAGON.

Exécution : python test_scanning_agent.py

ATTENTION : ce test émet du trafic actif vers la cible.
N'exécuter QUE sur des cibles dont vous avez l'autorisation légale.
"""

import json
import os
from datetime import datetime, timezone
from pentagon.agents.scanning_agent import ScanningAgent


def main():
    print("=" * 70)
    print("PENTAGON — Agent Scanning")
    print("=" * 70)
    
    # Cible : TechShop (application vulnérable du mémoire, autorisée)
    target = "techshop-vuln.rokina-sylla.me"
    scan_profile = "web_focused"
    
    # Initialise l'agent
    agent = ScanningAgent()
    
    # Lance l'agent
    result = agent.run(target=target, scan_profile=scan_profile)
    
    if result.get("status") == "error":
        print(f"\n❌ Échec : {result['error']}")
        return
    
    # Sauvegarde le résultat complet en JSON
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_file = f"results/scanning_{target}_{timestamp}.json"
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)
    
    # Affiche le résumé exécutif
    print("\n" + "=" * 70)
    print("RÉSUMÉ EXÉCUTIF — pour lecture humaine")
    print("=" * 70 + "\n")
    print(result.get("executive_summary", "Aucun résumé disponible."))
    
    # Statistiques
    print("\n" + "=" * 70)
    print("📊 STATISTIQUES")
    print("=" * 70)
    print(f"  Cible            : {result['target']}")
    print(f"  Phase PTES       : {result['ptes_phase']} (Threat Modeling)")
    print(f"  Tactique ATT&CK  : {result['attack_tactic']}")
    print(f"  Niveau de risque : {result['risk_level']}")
    print(f"  Profil de scan   : {result['scan_profile']}")
    print(f"  Durée            : {result['duration_seconds']:.2f}s")
    print(f"  Outils utilisés  : {', '.join(result['tools_used'])}")
    print(f"  Findings         : {len(result['analysis'].get('key_findings', []))}")
    print(f"  Confiance LLM    : {result['analysis'].get('confidence', 'N/A')}")
    print(f"\n  📂 Rapport JSON complet : {output_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
