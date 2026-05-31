"""
Exploration rapide du bundle JS de TechShop pour découvrir les endpoints API.

Exécution : python explore_bundle.py
"""

import re
import requests


def main():
    bundle_url = "https://techshop-vuln.rokina-sylla.me/assets/index-C5zfjJs0.js"
    
    print("=" * 70)
    print("Exploration du bundle JavaScript de TechShop")
    print("=" * 70)
    print(f"\n📥 Téléchargement de {bundle_url}")
    
    try:
        response = requests.get(bundle_url, timeout=30)
        print(f"   Status : {response.status_code}")
        print(f"   Taille : {len(response.text)} caractères")
    except Exception as e:
        print(f"   ❌ Erreur : {e}")
        return
    
    js_content = response.text
    
    # 1. Cherche les chemins /api/...
    print(f"\n🔍 ENDPOINTS API DÉCOUVERTS")
    print("-" * 70)
    api_paths = set(re.findall(r'["\'`](/api/[a-zA-Z0-9/_{}.$-]*)["\'`]', js_content))
    if api_paths:
        for path in sorted(api_paths):
            print(f"   • {path}")
    else:
        print("   Aucun chemin /api/ trouvé avec ce pattern.")
    
    # 2. Cherche d'autres patterns d'URL (sans /api)
    print(f"\n🔍 AUTRES CHEMINS POTENTIELS")
    print("-" * 70)
    other_paths = set(re.findall(r'["\'`](/[a-zA-Z][a-zA-Z0-9/_-]{2,40})["\'`]', js_content))
    # On filtre pour enlever les chemins d'assets et garder les routes intéressantes
    interesting = [p for p in other_paths if not p.startswith("/assets") 
                   and not p.endswith((".js", ".css", ".png", ".svg", ".jpg", ".ico"))]
    for path in sorted(interesting)[:40]:
        print(f"   • {path}")
    
    # 3. Cherche les URLs complètes (http://, https://)
    print(f"\n🔍 URLs COMPLÈTES RÉFÉRENCÉES")
    print("-" * 70)
    urls = set(re.findall(r'https?://[a-zA-Z0-9./_-]+', js_content))
    for url in sorted(urls)[:20]:
        print(f"   • {url}")
    
    # 4. Cherche les mots-clés sensibles
    print(f"\n🔍 MOTS-CLÉS SENSIBLES")
    print("-" * 70)
    keywords = ["token", "password", "secret", "apiKey", "api_key", "jwt", 
                "admin", "login", "auth", "Bearer"]
    for kw in keywords:
        count = len(re.findall(re.escape(kw), js_content, re.IGNORECASE))
        if count > 0:
            print(f"   • '{kw}' apparaît {count} fois")
    
    print("\n" + "=" * 70)
    print("Exploration terminée.")
    print("=" * 70)


if __name__ == "__main__":
    main()
