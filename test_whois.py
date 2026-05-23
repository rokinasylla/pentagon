"""
Test de l'outil WHOIS, indépendamment de tout agent ou LLM.

Exécution : python test_whois.py
"""

from pentagon.tools.whois_tool import run_whois


def main():
    print("=" * 60)
    print("PENTAGON — Test de l'outil WHOIS")
    print("=" * 60)
    
    # Liste de domaines à tester
    domains = [
        # Notre cible TechShop (domaine propriétaire de l'auteure)
        "rokina-sylla.me",
        "techshop-vuln.rokina-sylla.me",
        
        # Domaine de référence (devrait toujours marcher)
        "google.com",
        
        # Pour comparaison
        "uadb.edu.sn",
    ]
    
    for domain in domains:
        print(f"\n>>> WHOIS sur '{domain}'")
        print("-" * 60)
        
        result = run_whois(domain)
        
        if result["status"] == "success":
            print(f"  ✓ Registrar       : {result['registrar']}")
            print(f"  ✓ Organisation    : {result['org']}")
            print(f"  ✓ Pays            : {result['country']}")
            print(f"  ✓ Création        : {result['creation_date']}")
            print(f"  ✓ Expiration      : {result['expiration_date']}")
            print(f"  ✓ Serveurs DNS    : {result['name_servers'][:3]}")
            print(f"  ✓ Emails contact  : {result['emails'][:3]}")
        else:
            print(f"  ✗ Erreur : {result['error']}")
    
    print("\n" + "=" * 60)
    print("Test terminé.")
    print("=" * 60)


if __name__ == "__main__":
    main()
