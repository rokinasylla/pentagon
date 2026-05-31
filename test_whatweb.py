"""
Test de l'outil WhatWeb, indépendamment de tout agent.

Exécution : python test_whatweb.py
"""

from pentagon.tools.whatweb_tool import run_whatweb_scan


def main():
    print("=" * 70)
    print("PENTAGON — Test de l'outil WhatWeb")
    print("=" * 70)
    
    target = "https://techshop-vuln.rokina-sylla.me"
    
    print(f"\n🎯 Cible      : {target}")
    print(f"⚙️  Agression  : polite (3 requêtes)")
    print(f"⏳ Démarrage du scan WhatWeb (5-30 secondes)...")
    print("-" * 70)
    
    result = run_whatweb_scan(
        target_url=target,
        aggression="polite",
    )
    
    if result["status"] == "success":
        print(f"\n✓ Scan terminé en {result['duration_seconds']:.2f}s")
        print(f"  HTTP Status      : {result['http_status']}")
        print(f"  Niveau agression : {result['aggression_level']}")
        print(f"  Technologies     : {len(result['technologies'])}")
        
        print(f"\n📊 STACK INFÉRÉE")
        stack = result["inferred_stack"]
        print(f"  Frontend         : {stack['frontend'] or '(non détecté)'}")
        print(f"  Backend          : {stack['backend'] or '(non détecté)'}")
        print(f"  Serveur          : {stack['server'] or '(non détecté)'}")
        print(f"  CDN / WAF        : {stack['cdn_waf'] or '(non détecté)'}")
        print(f"  Signaux hosting  : {stack['hosting_signals'] or '(aucun)'}")
        
        if result["categories"]:
            print(f"\n📂 TECHNOLOGIES PAR CATÉGORIE")
            for category, techs in sorted(result["categories"].items()):
                print(f"\n  🏷️  {category.upper()}")
                for tech in techs:
                    values_str = f" → {', '.join(tech['values'])}" if tech["values"] else ""
                    print(f"     • {tech['name']}{values_str}")
        
        if result["sensitive_findings"]:
            print(f"\n🚨 EXPOSITIONS SENSIBLES ({len(result['sensitive_findings'])})")
            for f in result["sensitive_findings"]:
                values_str = f" → {', '.join(f['values'])}" if f["values"] else ""
                print(f"   ⚠️  {f['name']}{values_str}")
                print(f"      Raison : {f['reason']}")
        else:
            print(f"\n  ✓ Aucune exposition sensible détectée (bonne pratique)")
    else:
        print(f"\n✗ Erreur : {result['error']}")
    
    print("\n" + "=" * 70)
    print("Test terminé.")
    print("=" * 70)


if __name__ == "__main__":
    main()
