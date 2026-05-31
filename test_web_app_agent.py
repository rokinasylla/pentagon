"""
Test de l'Agent Web App de PENTAGON.

Exécution : python test_web_app_agent.py
"""

import json
import os
from datetime import datetime, timezone
from pentagon.agents.web_app_agent import WebAppAgent


def main():
    print("=" * 70)
    print("PENTAGON — Agent Web App")
    print("=" * 70)
    
    target = "techshop-vuln.rokina-sylla.me"
    
    agent = WebAppAgent()
    result = agent.run(target)
    
    # Sauvegarde
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_file = f"results/webapp_{target}_{timestamp}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)
    
    # Résumé exécutif
    print("\n" + "=" * 70)
    print("RÉSUMÉ EXÉCUTIF")
    print("=" * 70 + "\n")
    print(result.get("executive_summary", "N/A"))
    
    # Vulnérabilités détaillées
    analysis = result.get("analysis", {})
    vulns = analysis.get("vulnerabilities", [])
    
    print("\n" + "=" * 70)
    print(f"📊 VULNÉRABILITÉS DÉTECTÉES : {len(vulns)}")
    print("=" * 70)
    
    severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    for v in vulns:
        icon = severity_icons.get(v.get("severity", "info"), "⚪")
        print(f"\n{icon} [{v.get('severity', '?').upper()}] {v.get('title', 'Sans titre')}")
        print(f"   OWASP    : {v.get('owasp_top10', 'N/A')}")
        print(f"   CWE      : {v.get('cwe', 'N/A')}")
        print(f"   Endpoint : {v.get('affected_endpoint', 'N/A')}")
        print(f"   Remediation : {v.get('remediation', 'N/A')}")
    
    # Faux positifs écartés
    fp = analysis.get("false_positives_filtered", [])
    if fp:
        print(f"\n✅ FAUX POSITIFS ÉCARTÉS (jugement contextuel du LLM) :")
        for item in fp:
            print(f"   • {item}")
    
    print(f"\n  Risque global : {analysis.get('overall_risk', 'N/A')}")
    print(f"  📂 Rapport complet : {output_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
