"""Vérification rapide des endpoints du backend TechShop découverts dans le bundle."""

import requests

BASE = "https://techshop-backend-cc1t.onrender.com/api"

endpoints = [
    ("GET", "/products"),
    ("GET", "/users"),
    ("GET", "/users/me"),
    ("GET", "/orders"),
    ("GET", "/comments"),
    ("GET", "/admin"),
    ("POST", "/auth/login"),
    ("POST", "/auth/register"),
]

print("=" * 70)
print("Vérification des endpoints backend TechShop")
print(f"Base : {BASE}")
print("=" * 70)

for method, path in endpoints:
    url = BASE + path
    try:
        if method == "GET":
            r = requests.get(url, timeout=15)
        else:
            r = requests.post(url, json={}, timeout=15)
        ct = r.headers.get("content-type", "")[:30]
        print(f"  {method:4s} {path:25s} → {r.status_code}  [{ct}]")
    except Exception as e:
        print(f"  {method:4s} {path:25s} → ERREUR : {type(e).__name__}")

print("=" * 70)
