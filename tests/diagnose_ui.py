"""
Diagnostic UI (navigateur) — explore l'interface de TechShop pour repérer le
parcours réel : page de login, champs, et formulaire de commentaire.

Objectif : récupérer les vrais sélecteurs/routes afin de construire ensuite le
scénario de confirmation du XSS stocké. Ce n'est PAS un outil PENTAGON, c'est
une sonde manuelle (comme diagnose_xss.py).

Pré-requis : playwright + chromium installés.
Exécution : python tests/diagnose_ui.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

FRONTEND = "https://techshop-vuln.rokina-sylla.me"
LOGIN_CANDIDATES = ["/", "/login", "/signin", "/#/login", "/account/login"]


def dump_elements(page, label):
    print(f"\n--- {label} ---")
    print(f"URL: {page.url}")
    try:
        print(f"Titre: {page.title()}")
    except Exception:
        pass

    # Champs de saisie
    inputs = page.eval_on_selector_all(
        "input, textarea",
        """els => els.map(e => ({
            tag: e.tagName.toLowerCase(), type: e.type || '', name: e.name || '',
            id: e.id || '', placeholder: e.placeholder || ''
        }))""",
    )
    print(f"Champs ({len(inputs)}):")
    for i in inputs:
        print(f"   <{i['tag']}> type={i['type']} name='{i['name']}' id='{i['id']}' ph='{i['placeholder']}'")

    # Boutons
    buttons = page.eval_on_selector_all(
        "button, input[type=submit], [role=button]",
        "els => els.map(e => (e.innerText || e.value || '').trim()).filter(t => t)",
    )
    print(f"Boutons ({len(buttons)}): {buttons[:15]}")

    # Liens / routes (utile pour trouver une page produit)
    links = page.eval_on_selector_all(
        "a[href]",
        "els => [...new Set(els.map(e => e.getAttribute('href')))]",
    )
    print(f"Liens/routes ({len(links)}): {links[:25]}")


def main():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright non installé.")
        return

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_context().new_page()

        print("=" * 70)
        print("DIAGNOSTIC UI — TechShop")
        print("=" * 70)

        # 1. Page d'accueil
        try:
            page.goto(FRONTEND, wait_until="networkidle", timeout=40000)
            page.wait_for_timeout(1500)
            dump_elements(page, "ACCUEIL")
            page.screenshot(path="diag_accueil.png")
        except Exception as e:
            print(f"Accueil: erreur {type(e).__name__}: {e}")

        # 2. Candidats de page de login
        for path in LOGIN_CANDIDATES[1:]:
            try:
                page.goto(FRONTEND + path, wait_until="networkidle", timeout=30000)
                page.wait_for_timeout(1200)
                # n'affiche que si la page contient un champ password
                has_pw = page.query_selector("input[type=password]") is not None
                if has_pw:
                    dump_elements(page, f"LOGIN trouvé sur {path}")
                    page.screenshot(path="diag_login.png")
                    break
            except Exception as e:
                print(f"{path}: erreur {type(e).__name__}")

        print("\nCaptures: diag_accueil.png, diag_login.png (à ouvrir si besoin)")
        browser.close()
        print("\nDiagnostic UI terminé.")


if __name__ == "__main__":
    main()
