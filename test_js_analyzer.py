"""
Test de l'outil d'analyse JS, indépendamment de tout agent.

Exécution : python test_js_analyzer.py
"""

from pentagon.tools.js_analyzer_tool import run_js_analysis


def main():
    print("=" * 70)
    print("PENTAGON — Test de l'outil d'analyse JavaScript")
    print("=" * 70)
    
    target = "https://techshop-vuln.rokina-sylla.me"
    
    print(f"\n🎯 Cible : {target}")
    print(f"⏳ Analyse des bundles JavaScript...")
    print("-" * 70)
    
    result = run_js_analysis(target)
    
    if result["status"] in ("success", "partial"):
        print(f"\n✓ Analyse terminée en {result['duration_seconds']:.2f}s")
        print(f"  Bundles trouvés   : {len(result['bundles_found'])}")
        print(f"  Bundles analysés  : {result['bundles_analyzed']}")
        
        if result["bundles_found"]:
            print(f"\n📦 BUNDLES DÉCOUVERTS :")
            for b in result["bundles_found"]:
                print(f"   • {b}")
        
        if result["backend_urls"]:
            print(f"\n🌐 BACKENDS EXTERNES DÉTECTÉS (architecture découplée) :")
            for url in result["backend_urls"]:
                print(f"   • {url}")
        
        if result["api_endpoints"]:
            print(f"\n🔌 ENDPOINTS API DÉCOUVERTS ({len(result['api_endpoints'])}) :")
            for ep in result["api_endpoints"]:
                print(f"   • {ep}")
        
        if result["app_routes"]:
            print(f"\n🧭 ROUTES FRONTEND ({len(result['app_routes'])}) :")
            for route in result["app_routes"]:
                print(f"   • {route}")
        
        if result["sensitive_keywords"]:
            print(f"\n🔑 MOTS-CLÉS SENSIBLES :")
            for kw, count in sorted(result["sensitive_keywords"].items(), key=lambda x: -x[1]):
                print(f"   • {kw} : {count}x")
        
        if result["potential_secrets"]:
            print(f"\n🚨 SECRETS POTENTIELS ({len(result['potential_secrets'])}) :")
            for s in result["potential_secrets"]:
                print(f"   • [{s['type']}] {s['value_preview']}")
        
        if result["status"] == "partial":
            print(f"\n⚠️  Note : {result['error']}")
    else:
        print(f"\n✗ Erreur : {result['error']}")
    
    print("\n" + "=" * 70)
    print("Test terminé.")
    print("=" * 70)


if __name__ == "__main__":
    main()
