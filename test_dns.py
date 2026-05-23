"""
Test de l'outil DNS Lookup, indépendamment de tout agent.

Exécution : python test_dns.py
"""

import json
from pentagon.tools.dns_tool import run_dns_lookup


def main():
    print("=" * 70)
    print("PENTAGON — Test de l'outil DNS Lookup")
    print("=" * 70)
    
    domains = [
        "techshop-vuln.rokina-sylla.me",  # notre cible
        "rokina-sylla.me",                # domaine parent
        "google.com",                     # référence
        "uadb.edu.sn",                    # université
    ]
    
    for domain in domains:
        print(f"\n>>> DNS Lookup sur '{domain}'")
        print("-" * 70)
        
        result = run_dns_lookup(domain)
        
        print(f"  Status : {result['status']}")
        
        if result["records"]:
            for record_type, values in result["records"].items():
                # Limite l'affichage à 3 valeurs pour la lisibilité
                displayed = values[:3]
                more = f" ... (+{len(values) - 3})" if len(values) > 3 else ""
                print(f"  {record_type:6s}: {displayed}{more}")
        
        if result["inferred_hosting"]:
            print(f"  Hébergeur déduit : {result['inferred_hosting']}")
        
        if result["errors"]:
            print(f"  Erreurs : {result['errors']}")
    
    print("\n" + "=" * 70)
    print("Test terminé.")
    print("=" * 70)


if __name__ == "__main__":
    main()
