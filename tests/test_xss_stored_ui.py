"""
Confirmation du XSS STOCKÉ de TechShop via le parcours UI (navigateur).

Scénario : accueil → login (admin/admin123) → page produit → poster un
commentaire contenant un marqueur exécutant → vérifier si le script s'exécute.

Les sélecteurs ci-dessous sont la config propre à TechShop (observée via
diagnose_ui.py) ; l'outil xss_browser_tool reste générique.

Pré-requis : playwright + chromium.
Exécution : python tests/test_xss_stored_ui.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pentagon.tools.xss_browser_tool import confirm_stored_xss_ui

FRONTEND = "https://techshop-vuln.rokina-sylla.me"


def main():
    print("=" * 70)
    print("CONFIRMATION XSS STOCKÉ — TechShop (parcours UI navigateur)")
    print("=" * 70)
    print("Scénario : login admin → page produit → commentaire piégé → exécution ?\n")

    result = confirm_stored_xss_ui(
        base_url=FRONTEND,
        login_link="a[href='/login']",
        username_selector="input[type=text]",
        username_value="admin",
        password_selector="input[type=password]",
        password_value="admin123",
        login_button="button:has-text('Se connecter')",
        content_link="a[href='/products/1']",
        content_field="textarea",
        submit_button="button:has-text('Publier')",
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
        print("\n✅ XSS STOCKÉ PROUVÉ PAR EXÉCUTION RÉELLE → couverture 7/7 !")
    else:
        print("ℹ  Aucune exécution détectée : le frontend échappe probablement le")
        print("   contenu (pas de XSS), ou le scénario doit être ajusté.")
    print("=" * 70)


if __name__ == "__main__":
    main()
