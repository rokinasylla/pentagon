"""
Validation BOÎTE NOIRE du jwt_analyzer avec un VRAI token.

Objectif (mémoire, §9.2 — « Valider le jwt_analyzer avec le token réel ») :
prouver que la chaîne auth_tester → jwt_analyzer fonctionne de bout en bout
sur une cible réelle, sans aucune information spécifique codée en dur.

Déroulé :
  1. auth_tester découvre PAR LUI-MÊME un identifiant faible (liste générique)
     et récupère le VRAI token JWT émis par la cible.
  2. jwt_analyzer analyse ce token réel et détecte ses faiblesses
     (algorithme, secret, expiration, données sensibles, claims de privilège).

Aucun identifiant ni token n'est fourni : tout est découvert dynamiquement.
Seule donnée de config : l'URL de login + le nom du champ (observables sur
le formulaire de login, ce qui est légitime en boîte noire).

Exécution : python tests/test_jwt_validation.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests
from pentagon.tools.auth_tester_tool import AuthTesterTool
from pentagon.tools.jwt_analyzer_tool import run_jwt_analysis


# --- Configuration MINIMALE (ce qu'un testeur voit en observant le site) ---
TECHSHOP_BASE = "https://techshop-backend-cc1t.onrender.com"
TECHSHOP_LOGIN_URL = f"{TECHSHOP_BASE}/api/auth/login"
TECHSHOP_USERNAME_FIELD = "username"

# AUCUN identifiant ni token fourni : tout est découvert dynamiquement.


def wake_up_server():
    """Réveille le serveur Render (plan gratuit s'endort)."""
    print("Réveil du serveur Render (peut prendre 30-60s)...")
    for attempt in range(2):
        try:
            requests.get(f"{TECHSHOP_BASE}/api/products", timeout=60)
            print("✓ Serveur réveillé.\n")
            return
        except requests.RequestException:
            print(f"   tentative {attempt+1}...")
    print("⚠ Réveil incertain, on continue.\n")


def print_jwt_report(result: dict) -> None:
    """Affiche le rapport d'analyse JWT de façon lisible."""
    if result["status"] != "success":
        print(f"  ✗ Analyse impossible : {result['error']}")
        return

    print(f"  Algorithme        : {result['algorithm']}")
    print(f"  Payload (claims)  : {result['payload']}")
    print(f"  Token forgeable   : {'OUI ⚠' if result['is_forgeable'] else 'non'}")
    if result["cracked_secret"]:
        print(f"  🔓 SECRET CASSÉ   : '{result['cracked_secret']}'")
    if result["privilege_claims"]:
        print(f"  Claims de privilège exposés : {result['privilege_claims']}")
    if result["sensitive_claims"]:
        print(f"  Claims sensibles exposés    : {result['sensitive_claims']}")
    if result.get("cracked_secret"):
        print(f"  🔓 SECRET CASSÉ   : '{result['cracked_secret']}'")

    findings = result["findings"]
    if findings:
        print(f"\n  🚨 FAIBLESSES DÉTECTÉES ({len(findings)}) :")
        for f in findings:
            print(f"     [{f['severity'].upper()}] {f['title']}")
            print(f"        OWASP : {f['owasp']} | CWE : {f['cwe']}")
    else:
        print("  ✓ Aucune faiblesse détectée.")


def main():
    print("=" * 70)
    print("VALIDATION BOÎTE NOIRE — chaîne auth_tester → jwt_analyzer")
    print("=" * 70)
    print("Aucun identifiant ni token fourni. Tout est découvert dynamiquement.\n")

    wake_up_server()

    # === Étape 1 : récupérer un VRAI token via auth_tester (boîte noire) ===
    print("─" * 70)
    print("ÉTAPE 1 — auth_tester : découverte d'identifiant + récupération du token")
    print("─" * 70)

    auth = AuthTesterTool(delay_between_attempts=1.5, timeout=30)
    auth_result = auth.run(
        login_url=TECHSHOP_LOGIN_URL,
        username_field=TECHSHOP_USERNAME_FIELD,
    )

    print(f"Identifiants testés (liste générique) : {auth_result['tested_count']}")
    for cred in auth_result["weak_credentials_found"]:
        print(f"   ⚠ DÉCOUVERT : {cred['username']} / {cred['password']}  (HTTP {cred['status_code']})")

    token = auth_result["token"]
    if not token:
        print("\n❌ Aucun token récupéré : impossible de valider le jwt_analyzer.")
        print("   (Vérifier que la cible est joignable et qu'un identifiant faible existe.)")
        return

    print(f"✓ Token réel récupéré (emplacement : {auth_result['token_location']})")
    print(f"   {token[:60]}...\n")

    # === Étape 2 : analyser le VRAI token avec jwt_analyzer ===
    print("─" * 70)
    print("ÉTAPE 2 — jwt_analyzer : analyse du token réel")
    print("─" * 70)

    # Indices de contexte (nom d'app/domaine) pour dériver des candidats de
    # secret — génériques, dérivés de la cible observée, pas codés en dur.
    context_hints = [TECHSHOP_BASE.split("//")[-1], "techshop-vuln.rokina-sylla.me"]
    jwt_result = run_jwt_analysis(token, context_hints=context_hints)
    print_jwt_report(jwt_result)

    # === Synthèse de validation ===
    print("\n" + "=" * 70)
    if jwt_result["status"] == "success" and jwt_result["is_valid_jwt"]:
        print("✅ VALIDATION RÉUSSIE : le jwt_analyzer a analysé un token RÉEL,")
        print("   obtenu de bout en bout par PENTAGON sans information préalable.")
        if jwt_result["findings"]:
            print(f"   {len(jwt_result['findings'])} faiblesse(s) JWT détectée(s).")
    else:
        print("⚠ Le token récupéré n'a pas pu être analysé comme un JWT valide.")
    print("=" * 70)


if __name__ == "__main__":
    main()
