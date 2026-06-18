"""
Validation BOÎTE NOIRE du sqli_tester sur TechShop.

Teste les deux vecteurs : contournement d'authentification sur le login, et
injection sur un endpoint paramétré. Aucune donnée spécifique codée en dur
au-delà de l'URL de login et d'un gabarit d'endpoint (observables sur l'app).

Charges strictement non destructives.

Exécution : python tests/test_sqli_validation.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests
from pentagon.tools.auth_tester_tool import AuthTesterTool
from pentagon.tools.sqli_tester_tool import run_sqli_test


TECHSHOP_BASE = "https://techshop-backend-cc1t.onrender.com"
TECHSHOP_LOGIN_URL = f"{TECHSHOP_BASE}/api/auth/login"
INJECTABLE_ENDPOINTS = [f"{TECHSHOP_BASE}/api/users/{{id}}", f"{TECHSHOP_BASE}/api/orders/{{id}}"]


def wake_up_server():
    print("Réveil du serveur Render (peut prendre 30-60s)...")
    for attempt in range(2):
        try:
            requests.get(f"{TECHSHOP_BASE}/api/products", timeout=60)
            print("✓ Serveur réveillé.\n")
            return
        except requests.RequestException:
            print(f"   tentative {attempt+1}...")
    print("⚠ Réveil incertain, on continue.\n")


def main():
    print("=" * 70)
    print("VALIDATION BOÎTE NOIRE — sqli_tester sur TechShop")
    print("=" * 70)

    wake_up_server()

    # Un token (facultatif) pour atteindre les endpoints protégés
    auth = AuthTesterTool(delay_between_attempts=1.5, timeout=30)
    token = auth.run(login_url=TECHSHOP_LOGIN_URL, username_field="username").get("token")
    print(f"Token disponible pour les endpoints protégés : {'OUI' if token else 'NON'}\n")

    result = run_sqli_test(
        login_url=TECHSHOP_LOGIN_URL,
        injectable_endpoints=INJECTABLE_ENDPOINTS,
        token=token,
    )

    print(f"Cibles testées : {result['endpoints_tested']}")
    for r in result["results"]:
        print(f"\n  Vecteur : {r['vector']} — {r['target']}")
        if r.get("notes"):
            for n in r["notes"]:
                print(f"    note : {n}")

    findings = result["sqli_findings"]
    if findings:
        print(f"\n  🚨 FINDINGS SQLi ({len(findings)}) :")
        for f in findings:
            print(f"     [{f['severity'].upper()}] {f['title']} — {f['target']}")
            print(f"        {f['owasp']} | CWE : {f['cwe']} | vecteur : {f['vector']}")
            print(f"        preuve : {f['evidence']}")

    print("\n" + "=" * 70)
    if findings:
        print("✅ SQLi PROUVÉE par attaque réelle.")
    else:
        print("ℹ  Aucune SQLi confirmée sur les cibles testées.")
    print("=" * 70)


if __name__ == "__main__":
    main()
