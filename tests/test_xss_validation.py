"""
Validation BOÎTE NOIRE du xss_tester sur TechShop.

Teste le XSS réfléchi (paramètres) et le XSS stocké (POST d'un marqueur inerte
sur une collection, puis relecture). Marqueur NON exécutable.

Exécution : python tests/test_xss_validation.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests
from pentagon.tools.auth_tester_tool import AuthTesterTool
from pentagon.tools.xss_tester_tool import run_xss_test


TECHSHOP_BASE = "https://techshop-backend-cc1t.onrender.com"
TECHSHOP_LOGIN_URL = f"{TECHSHOP_BASE}/api/auth/login"

# Cibles observables sur l'app (génériques)
REFLECTED_URLS = [f"{TECHSHOP_BASE}/api/products"]
STORED_COLLECTIONS = [f"{TECHSHOP_BASE}/api/comments"]


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
    print("VALIDATION BOÎTE NOIRE — xss_tester sur TechShop")
    print("=" * 70)

    wake_up_server()

    auth = AuthTesterTool(delay_between_attempts=1.5, timeout=30)
    token = auth.run(login_url=TECHSHOP_LOGIN_URL, username_field="username").get("token")
    print(f"Token disponible : {'OUI' if token else 'NON'}\n")

    result = run_xss_test(
        reflected_urls=REFLECTED_URLS,
        stored_collections=STORED_COLLECTIONS,
        token=token,
    )

    print(f"Cibles testées : {result['targets_tested']}")
    for r in result["results"]:
        print(f"\n  Vecteur : {r['vector']} — {r['target']}")
        for n in r.get("notes", []):
            print(f"    note : {n}")

    findings = result["xss_findings"]
    if findings:
        print(f"\n  🚨 FINDINGS XSS ({len(findings)}) :")
        for f in findings:
            print(f"     [{f['severity'].upper()}] {f['title']} — {f['target']}")
            print(f"        {f['owasp']} | CWE : {f['cwe']} | vecteur : {f['vector']}")
            print(f"        preuve : {f['evidence']}")

    print("\n" + "=" * 70)
    if findings:
        print("✅ XSS PROUVÉ par attaque réelle (réflexion/stockage non échappé).")
    else:
        print("ℹ  Aucun XSS confirmé sur les cibles testées.")
    print("=" * 70)


if __name__ == "__main__":
    main()
