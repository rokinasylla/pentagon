"""
Test de l'outil d'analyse des headers de sécurité.

Exécution : python test_security_headers.py
"""

from pentagon.tools.security_headers_tool import run_security_headers_scan


def main():
    print("=" * 70)
    print("PENTAGON — Test de l'analyse des headers de sécurité")
    print("=" * 70)
    
    # On teste à la fois le frontend et le backend
    targets = [
        "https://techshop-vuln.rokina-sylla.me",
        "https://techshop-backend-cc1t.onrender.com/api/products",
    ]
    
    for target in targets:
        print(f"\n{'━' * 70}")
        print(f"🎯 Cible : {target}")
        print(f"{'━' * 70}")
        
        result = run_security_headers_scan(target)
        
        if result["status"] == "success":
            print(f"  HTTP Status     : {result['http_status']}")
            print(f"  🛡️  Score sécurité : {result['security_score']}/100")
            
            if result["missing_security_headers"]:
                print(f"\n  ⚠️  HEADERS DE SÉCURITÉ MANQUANTS ({result['summary']['missing_count']}) :")
                for h in result["missing_security_headers"]:
                    icon = "🔴" if h["severity"] == "high" else "🟠" if h["severity"] == "medium" else "🟡"
                    print(f"     {icon} [{h['severity']:6s}] {h['header']}")
                    print(f"             {h['description']}")
            
            if result["present_security_headers"]:
                print(f"\n  ✅ HEADERS DE SÉCURITÉ PRÉSENTS :")
                for h in result["present_security_headers"]:
                    print(f"     • {h['header']}")
            
            if result["info_disclosure_headers"]:
                print(f"\n  🔓 FUITES D'INFORMATION ({result['summary']['info_leaks_count']}) :")
                for h in result["info_disclosure_headers"]:
                    print(f"     • {h['header']}: {h['value']}")
                    print(f"       → {h['description']}")
            
            if result["cookie_issues"]:
                print(f"\n  🍪 PROBLÈMES DE COOKIES ({result['summary']['cookie_issues_count']}) :")
                for c in result["cookie_issues"]:
                    print(f"     • Cookie '{c['cookie_name']}' :")
                    for issue in c["issues"]:
                        print(f"        - {issue}")
            else:
                print(f"\n  🍪 Pas de cookie défaillant détecté")
        else:
            print(f"  ✗ Erreur : {result['error']}")
    
    print("\n" + "=" * 70)
    print("Test terminé.")
    print("=" * 70)


if __name__ == "__main__":
    main()
