"""
Test de l'outil API Prober.

Exécution : python test_api_prober.py

Cet outil enchaîne avec l'analyseur JS : il découvre d'abord les endpoints,
puis les teste — démontrant la chaîne générique de découverte + sondage.
"""

from pentagon.tools.js_analyzer_tool import run_js_analysis
from pentagon.tools.api_prober_tool import run_api_probe


def main():
    print("=" * 70)
    print("PENTAGON — Test de l'outil API Prober (avec découverte JS)")
    print("=" * 70)
    
    target = "https://techshop-vuln.rokina-sylla.me"
    
    # Étape 1 : découvrir les endpoints via l'analyseur JS
    print(f"\n📡 Phase 1 : Découverte des endpoints via analyse JS...")
    js_result = run_js_analysis(target)
    
    # Détermine le base_url backend et les endpoints à tester
    backend_urls = js_result.get("backend_urls", [])
    routes = js_result.get("app_routes", [])
    
    if backend_urls:
        # Architecture découplée : on utilise le backend découvert
        base_url = backend_urls[0]
        print(f"   ✓ Backend découplé détecté : {base_url}")
    else:
        # Pas de backend séparé : on teste sur la cible directement
        base_url = target
        print(f"   ✓ Pas de backend séparé, test sur la cible : {base_url}")
    
    # Les routes deviennent les endpoints à tester
    # On nettoie le base_url (enlève /api s'il est déjà dedans pour éviter doublon)
    print(f"   ✓ {len(routes)} routes/endpoints à tester")
    
    # Étape 2 : sonder les endpoints
    print(f"\n🔍 Phase 2 : Sondage des endpoints (sans authentification)...")
    print("-" * 70)
    
    probe_result = run_api_probe(base_url=base_url, endpoints=routes)
    
    # Affichage des résultats
    print(f"\n✓ Sondage terminé en {probe_result['duration_seconds']:.2f}s")
    print(f"  Endpoints testés : {probe_result['endpoints_tested']}")
    
    s = probe_result["summary"]
    print(f"\n📊 RÉSUMÉ")
    print(f"   • Accessibles sans auth : {s['accessible_without_auth']}")
    print(f"   • Protégés (401/403)    : {s['protected']}")
    print(f"   • Erreurs               : {s['errors']}")
    print(f"   • Données sensibles      : {s['sensitive_data_exposed']}")
    
    # Détail de tous les endpoints
    print(f"\n📋 DÉTAIL PAR ENDPOINT")
    for r in probe_result["results"]:
        code = r["status_code"] if r["status_code"] else "ERR"
        json_flag = "JSON" if r["returns_json"] else "    "
        count = f" [{r['record_count']} items]" if r["record_count"] is not None else ""
        print(f"   {str(code):4s} {json_flag}  {r['endpoint']}{count}")
    
    # Findings de contrôle d'accès
    if probe_result["access_control_findings"]:
        print(f"\n🚨 BROKEN ACCESS CONTROL ({len(probe_result['access_control_findings'])}) :")
        for f in probe_result["access_control_findings"]:
            print(f"   ⚠️  {f['endpoint']} → {f['reason']}")
            print(f"       OWASP : {f['owasp']}")
    
    # Findings d'exposition de données
    if probe_result["data_exposure_findings"]:
        print(f"\n🔓 EXPOSITION DE DONNÉES SENSIBLES ({len(probe_result['data_exposure_findings'])}) :")
        for f in probe_result["data_exposure_findings"]:
            print(f"   🚨 {f['endpoint']}")
            print(f"       Champs sensibles : {', '.join(f['sensitive_fields'])}")
            print(f"       OWASP : {f['owasp']}")
    
    print("\n" + "=" * 70)
    print("Test terminé.")
    print("=" * 70)


if __name__ == "__main__":
    main()
