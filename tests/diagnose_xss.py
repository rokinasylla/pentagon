"""
Diagnostic XSS — explore la structure réelle de TechShop pour localiser les
points d'injection (commentaires/avis) et tester la réflexion.

Ce script N'EST PAS un outil PENTAGON : c'est une sonde manuelle pour
comprendre la cible et ajuster le xss_tester ensuite.

Exécution : python tests/diagnose_xss.py
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import requests
from pentagon.tools.auth_tester_tool import AuthTesterTool

BASE = "https://techshop-backend-cc1t.onrender.com"
LOGIN = f"{BASE}/api/auth/login"
MARKER = "<pgnxss7s9>"

# Endpoints candidats où des commentaires/avis pourraient vivre
COMMENT_CANDIDATES = [
    "/api/comments",
    "/api/reviews",
    "/api/products/1/comments",
    "/api/products/1/reviews",
    "/api/feedback",
    "/api/messages",
    "/api/contact",
]

# Endpoints candidats pour une réflexion (recherche)
REFLECT_CANDIDATES = [
    "/api/products?search=" + MARKER,
    "/api/products?q=" + MARKER,
    "/api/search?q=" + MARKER,
    "/api/products/search?q=" + MARKER,
]


def wake():
    print("Réveil du serveur...")
    for _ in range(2):
        try:
            requests.get(f"{BASE}/api/products", timeout=60); print("✓\n"); return
        except requests.RequestException:
            pass
    print("⚠ on continue\n")


def main():
    wake()
    token = AuthTesterTool(delay_between_attempts=1.5, timeout=30).run(
        login_url=LOGIN, username_field="username").get("token")
    headers = {"User-Agent": "PENTAGON-diag/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    print(f"Token : {'OUI' if token else 'NON'}\n")

    print("=" * 70)
    print("1) COMMENTAIRES / AVIS — GET (structure & schéma)")
    print("=" * 70)
    for path in COMMENT_CANDIDATES:
        url = BASE + path
        try:
            r = requests.get(url, headers=headers, timeout=30)
        except requests.RequestException as e:
            print(f"  {path:32} ERREUR {type(e).__name__}")
            continue
        ctype = r.headers.get("content-type", "")[:30]
        info = f"  {path:32} {r.status_code}  {ctype}"
        # Si JSON, montre les clés d'un objet exemple
        try:
            data = r.json()
            if isinstance(data, list):
                info += f"  liste[{len(data)}]"
                if data and isinstance(data[0], dict):
                    info += f" clés={list(data[0].keys())}"
            elif isinstance(data, dict):
                info += f"  objet clés={list(data.keys())[:8]}"
        except ValueError:
            info += f"  (non-JSON, {len(r.content)}o)"
        print(info)

    print("\n" + "=" * 70)
    print("2) RÉFLEXION — GET avec marqueur (recherche)")
    print("=" * 70)
    for path in REFLECT_CANDIDATES:
        url = BASE + path
        try:
            r = requests.get(url, headers=headers, timeout=30)
        except requests.RequestException as e:
            print(f"  {path:40} ERREUR {type(e).__name__}")
            continue
        body = r.text or ""
        ctype = r.headers.get("content-type", "")[:30]
        raw = MARKER in body
        escaped = "&lt;pgnxss7s9&gt;" in body
        verdict = "REFLÉTÉ BRUT ⚠" if raw and not escaped else ("échappé (sûr)" if escaped else "non reflété")
        print(f"  {path:40} {r.status_code}  [{ctype}]  {verdict}")
        # Si reflété brut, montre le contexte (HTML vs JSON) autour du marqueur
        if raw and not escaped:
            idx = body.find(MARKER)
            snippet = body[max(0, idx - 60): idx + len(MARKER) + 30].replace("\n", " ")
            print(f"       contexte: ...{snippet}...")

    print("\nDiagnostic terminé.")


if __name__ == "__main__":
    main()
