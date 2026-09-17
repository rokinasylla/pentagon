"""
Confirmation du XSS STOCKE de VulnShop via le parcours UI (navigateur).

VulnShop est la 2e cible d'entrainement de PENTAGON (Node/Express + SPA),
hebergee en ligne (ex. Render). Ce test prouve l'EXECUTION reelle d'un XSS
stocke, comme pour TechShop, en pilotant un vrai navigateur.

Scenario : accueil → login (admin/admin123) → page produit → poster un
commentaire piege → verifier si le script s'execute au rendu.

Les selecteurs ci-dessous sont la config propre a VulnShop (ids stables definis
dans public/assets/app.js) ; l'outil xss_browser_tool reste generique.

Pre-requis : playwright + chromium.
Execution : FRONTEND=<url> python tests/test_vulnshop_xss_stored_ui.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pentagon.tools.xss_browser_tool import confirm_stored_xss_ui

# URL publique de VulnShop (surchargée par la variable d'env FRONTEND).
FRONTEND = os.environ.get("FRONTEND", "https://vulnshop.onrender.com")


def main():
    print("=" * 70)
    print("CONFIRMATION XSS STOCKE — VulnShop (parcours UI navigateur)")
    print("=" * 70)
    print(f"Cible : {FRONTEND}")
    print("Scenario : login admin → page produit → commentaire piege → execution ?\n")

    result = confirm_stored_xss_ui(
        base_url=FRONTEND,
        login_link="#login-link",
        username_selector="#username",
        username_value="admin",
        password_selector="#password",
        password_value="admin123",
        login_button="#login-btn",
        content_link="#product-1",
        content_field="#comment-input",
        submit_button="#comment-btn",
        headless=True,
    )

    if result["status"] != "success":
        print(f"✗ Erreur : {result['error']}")
        return

    for note in result["notes"]:
        print(f"  - {note}")

    print("\n" + "=" * 70)
    if result["confirmed"]:
        f = result["finding"]
        print(f"🚨 {f['title']}")
        print(f"   {f['owasp']} | CWE : {f['cwe']} | {f['vector']}")
        print(f"   preuve : {f['evidence']}")
        print("\n✅ XSS STOCKE PROUVE PAR EXECUTION REELLE sur la 2e cible !")
    else:
        print("ℹ  Aucune execution detectee : verifier que le service est bien reveille")
        print("   (Render free tier s'endort), ou ajuster le scenario.")
    print("=" * 70)


if __name__ == "__main__":
    main()
