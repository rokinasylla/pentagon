"""Inspection du contenu réel des endpoints suspects de TechShop."""

import requests
import json

BASE = "https://techshop-backend-cc1t.onrender.com/api"

# Endpoints qui ont répondu 200 sans authentification
suspects = ["/products", "/users", "/orders"]

print("=" * 70)
print("Inspection du contenu des endpoints publics")
print("=" * 70)

for path in suspects:
    url = BASE + path
    print(f"\n{'─' * 70}")
    print(f">>> GET {path}")
    print(f"{'─' * 70}")
    try:
        r = requests.get(url, timeout=20)
        print(f"Status : {r.status_code}")
        
        # Tente de parser en JSON
        try:
            data = r.json()
            # Affiche un aperçu limité (premiers éléments)
            preview = json.dumps(data, indent=2, ensure_ascii=False)
            # Limite à 1500 caractères pour ne pas tout afficher
            if len(preview) > 1500:
                print(preview[:1500])
                print(f"\n... [tronqué — réponse totale : {len(preview)} caractères]")
            else:
                print(preview)
            
            # Si c'est une liste, compte les éléments
            if isinstance(data, list):
                print(f"\n📊 Nombre d'éléments : {len(data)}")
            elif isinstance(data, dict):
                print(f"\n📊 Clés : {list(data.keys())}")
        except Exception:
            # Pas du JSON, affiche le texte brut
            print(f"Contenu (texte) : {r.text[:500]}")
    except Exception as e:
        print(f"❌ Erreur : {type(e).__name__}: {e}")

print("\n" + "=" * 70)
