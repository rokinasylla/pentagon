"""
Test de l'outil crt.sh, indépendamment de tout agent.

Exécution : python test_crtsh.py
"""

from pentagon.tools.crtsh_tool import run_crtsh_lookup


def main():
    print("=" * 70)
    print("PENTAGON — Test de l'outil crt.sh (Certificate Transparency)")
    print("=" * 70)
    
    # Liste de domaines à tester
    domains = [
        "rokina-sylla.me",          # ton domaine
        "uadb.edu.sn",              # ton université  
        "github.com",               # référence — devrait avoir beaucoup de certs
    ]
    
    for domain in domains:
        print(f"\n>>> Lookup crt.sh sur '{domain}'")
        print("-" * 70)
        print("  ⏳ Interrogation de crt.sh (peut prendre 10-30 secondes)...")
        
        result = run_crtsh_lookup(domain)
        
        if result["status"] == "success" and result["total_certificates"] > 0:
            print(f"  ✓ {result['total_certificates']} certificats trouvés")
            print(f"  ⏱️  Durée : {result['lookup_duration_seconds']:.2f}s")
            
            print(f"\n  📜 SOUS-DOMAINES DÉCOUVERTS ({result['summary']['subdomains_count']}) :")
            for sub in result["unique_subdomains"][:15]:  # max 15 affichés
                print(f"     • {sub}")
            if len(result["unique_subdomains"]) > 15:
                print(f"     ... et {len(result['unique_subdomains']) - 15} autres")
            
            print(f"\n  🏛️  AUTORITÉS DE CERTIFICATION ({result['summary']['ca_count']}) :")
            for ca in result["certificate_authorities"]:
                print(f"     • {ca}")
            
            print(f"\n  🔣 WILDCARDS : {result['summary']['wildcard_certificates']}")
            print(f"  📅 PREMIER CERT : {result['first_certificate_date']}")
            print(f"  📅 DERNIER CERT : {result['latest_certificate_date']}")
            
        elif result["status"] == "success":
            print(f"  ⚠️  {result.get('error', 'Aucun certificat trouvé')}")
        else:
            print(f"  ✗ Erreur : {result['error']}")
    
    print("\n" + "=" * 70)
    print("Test terminé.")
    print("=" * 70)


if __name__ == "__main__":
    main()
