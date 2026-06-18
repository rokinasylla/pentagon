"""
Validation du confirmateur XSS par navigateur (Playwright).

1. SELF-TEST : prouve que Playwright + la détection d'exécution fonctionnent
   (charge une page locale exécutante, sans cible).
2. Sur TechShop : tente de confirmer un XSS réfléchi sur les endpoints de
   recherche candidats.

Pré-requis : pip install playwright && playwright install chromium
Exécution : python tests/test_xss_browser.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pentagon.tools.xss_browser_tool import self_test, confirm_reflected_xss


BASE = "https://techshop-backend-cc1t.onrender.com"
REFLECTED_CANDIDATES = [
    f"{BASE}/api/products/search",
    f"{BASE}/api/products",
]


def main():
    print("=" * 70)
    print("VALIDATION — confirmateur XSS par navigateur (Playwright)")
    print("=" * 70)

    # 1. Self-test (vérifie l'installation et la détection)
    print("\n[1] Self-test de la chaîne Playwright + détection...")
    st = self_test()
    if st["ok"]:
        print("    ✓ Playwright fonctionne et la détection d'exécution est opérationnelle.")
    else:
        print(f"    ✗ Échec : {st['error']}")
        print("    → Installez : pip install playwright && playwright install chromium")
        return

    # 2. Confirmation sur TechShop
    print("\n[2] Tentative de confirmation XSS réfléchi sur TechShop...")
    result = confirm_reflected_xss(REFLECTED_CANDIDATES)

    if result["status"] != "success":
        print(f"    ✗ {result['error']}")
        return

    findings = result["confirmed_findings"]
    print(f"    URLs testées : {result['urls_tested']}")
    if findings:
        print(f"\n  🚨 XSS CONFIRMÉS PAR EXÉCUTION ({len(findings)}) :")
        for f in findings:
            print(f"     [{f['severity'].upper()}] {f['target']} (param {f['parameter']})")
    else:
        print("    ℹ  Aucun XSS réfléchi confirmé sur ces endpoints "
              "(cohérent : la réflexion observée est en text/plain = SQLi, pas HTML).")

    print("\n" + "=" * 70)
    print("Self-test OK = l'outil est prêt. Le XSS stocké de TechShop nécessitera")
    print("un scénario UI (login + formulaire de commentaire) — étape suivante.")
    print("=" * 70)


if __name__ == "__main__":
    main()
