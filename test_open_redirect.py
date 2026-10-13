#!/usr/bin/env python3
"""
Tests PURS du testeur Open Redirect
(pentagon/tools/open_redirect_tester_tool.py). Aucun réseau.
"""

from pentagon.tools.open_redirect_tester_tool import (
    _redirect_is_external, _candidate_endpoints, CANARY_HOST,
    COMMON_REDIRECT_PATHS,
)

results = []


def check(name, condition):
    results.append(condition)
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def test_external_detection():
    print("test_external_detection")
    check("https externe -> vrai",
          _redirect_is_external(f"https://{CANARY_HOST}/", CANARY_HOST))
    check("protocole-relatif -> vrai",
          _redirect_is_external(f"//{CANARY_HOST}/x", CANARY_HOST))
    check("relatif interne -> faux",
          not _redirect_is_external("/dashboard", CANARY_HOST))
    check("autre domaine -> faux",
          not _redirect_is_external("https://autre.example/", CANARY_HOST))
    check("vide -> faux", not _redirect_is_external("", CANARY_HOST))


def test_candidate_endpoints():
    print("test_candidate_endpoints")
    eps = _candidate_endpoints("https://v.me",
                               ["/api/go", "/api/products", "/logout"])
    check("chemins courants inclus",
          all(("https://v.me" + p) in eps for p in COMMON_REDIRECT_PATHS))
    check("endpoint 'logout' (redirect-ish) inclus", "https://v.me/logout" in eps)
    check("endpoint 'products' exclu", "https://v.me/api/products" not in eps)


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — open_redirect_tester_tool")
    print("=" * 70)
    for t in (test_external_detection, test_candidate_endpoints):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
