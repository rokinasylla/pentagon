#!/usr/bin/env python3
"""
Tests PURS du testeur SSRF (pentagon/tools/ssrf_tester_tool.py).

Aucun réseau : on valide la détection du signal de requête sortante (canari +
signature réseau), l'extraction d'origine et la construction des endpoints
candidats. L'attaque réelle est validée séparément sur VulnShop.
"""

from pentagon.tools.ssrf_tester_tool import (
    _is_ssrf_signal, _base_origin, _candidate_endpoints,
    COMMON_FETCH_PATHS, CANARY_HOST,
)

results = []


def check(name, condition):
    results.append(condition)
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def test_is_ssrf_signal():
    print("test_is_ssrf_signal")
    check("erreur de résolution du canari -> oui",
          _is_ssrf_signal(f"getaddrinfo ENOTFOUND {CANARY_HOST}", CANARY_HOST))
    check("corps récupéré référant le canari -> oui",
          _is_ssrf_signal(f'{{"fetchedUrl":"http://{CANARY_HOST}/","status":502}}',
                          CANARY_HOST))
    check("canari absent -> non",
          not _is_ssrf_signal("getaddrinfo ENOTFOUND autre.example", CANARY_HOST))
    check("canari réfléchi sans signature réseau -> non",
          not _is_ssrf_signal(f"Vous avez demandé {CANARY_HOST}", CANARY_HOST))
    check("vide -> non", not _is_ssrf_signal("", CANARY_HOST))


def test_base_origin():
    print("test_base_origin")
    check("origine depuis URL",
          _base_origin("https://v.me/api/x?y=1") == "https://v.me")
    check("origine depuis domaine nu", _base_origin("v.me") == "https://v.me")


def test_candidate_endpoints():
    print("test_candidate_endpoints")
    eps = _candidate_endpoints("https://v.me",
                               ["/api/fetch", "/api/login",
                                "/api/proxy?u=1", "/api/products"])
    check("chemins de fetch courants inclus",
          all(("https://v.me" + p) in eps for p in COMMON_FETCH_PATHS))
    check("endpoint 'proxy' inclus", "https://v.me/api/proxy" in eps)
    check("endpoint 'login' exclu", "https://v.me/api/login" not in eps)
    check("endpoint 'products' exclu", "https://v.me/api/products" not in eps)
    check("pas de doublon /api/fetch",
          eps.count("https://v.me/api/fetch") == 1)


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — ssrf_tester_tool")
    print("=" * 70)
    for t in (test_is_ssrf_signal, test_base_origin, test_candidate_endpoints):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
