"""
Test du auth_tester en BOÎTE NOIRE sur TechShop.

L'outil ne reçoit AUCUN identifiant spécifique à la cible.
Il utilise uniquement sa liste générique d'identifiants par défaut.
On observe ce qu'il découvre PAR LUI-MÊME.

Seule donnée de config : l'URL de login et le nom du champ
(informations qu'un testeur obtient en observant le formulaire de login,
ce qui est légitime même en boîte noire).

Exécution : python tests/test_auth_tester.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests
from pentagon.tools.auth_tester_tool import AuthTesterTool


# --- Configuration MINIMALE (ce qu'un testeur voit en observant le site) ---
TECHSHOP_BASE = "https://techshop-backend-cc1t.onrender.com"
TECHSHOP_LOGIN_URL = f"{TECHSHOP_BASE}/api/auth/login"
# Le nom du champ est observable dans le formulaire de login (légitime)
TECHSHOP_USERNAME_FIELD = "username"

# AUCUN identifiant fourni ! L'outil utilise SA liste générique.


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


def main():
    print("=" * 70)
    print("TEST BOÎTE NOIRE — auth_tester sur TechShop")
    print("=" * 70)
    print("L'outil n'a AUCUN identifiant de la cible.")
    print("Il utilise uniquement sa liste générique par défaut.\n")

    wake_up_server()

    tool = AuthTesterTool(delay_between_attempts=1.5, timeout=30)

    # On ne passe PAS de credentials → l'outil utilise sa liste générique
    result = tool.run(
        login_url=TECHSHOP_LOGIN_URL,
        username_field=TECHSHOP_USERNAME_FIELD,
    )

    print(f"Identifiants testés (liste générique) : {result['tested_count']}")
    print(f"Identifiants faibles DÉCOUVERTS       : {len(result['weak_credentials_found'])}")
    for cred in result["weak_credentials_found"]:
        print(f"   ⚠ DÉCOUVERT : {cred['username']} / {cred['password']}  (HTTP {cred['status_code']})")
    print(f"Token récupéré : {'OUI' if result['token'] else 'NON'}")
    if result["token"]:
        print(f"   Emplacement : {result['token_location']}")
        print(f"   Token (60 1ers car.) : {result['token'][:60]}...")

    print("\nNotes :")
    for note in result["notes"]:
        print(f"   - {note}")

    print("\n" + "=" * 70)
    if result["weak_credentials_found"]:
        print("✅ L'outil a découvert des identifiants faibles PAR LUI-MÊME.")
    else:
        print("ℹ  Aucun identifiant générique n'a matché (la cible n'utilise")
        print("   pas d'identifiants par défaut très courants).")
    print("=" * 70)


if __name__ == "__main__":
    main()
