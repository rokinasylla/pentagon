#!/usr/bin/env python3
"""
Tests PURS du testeur CSRF (pentagon/tools/csrf_tester_tool.py).

Aucun réseau : on valide la détection d'absence de SameSite, le marqueur de
changement d'état, l'extraction d'origine et la construction des endpoints
candidats. L'attaque réelle (requête inter-site) est validée sur VulnShop.
"""

from pentagon.tools.csrf_tester_tool import (
    _samesite_missing, _looks_state_changed, _base_origin, _candidate_endpoints,
    COMMON_STATE_PATHS,
)

results = []


def check(name, condition):
    results.append(condition)
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def test_samesite_missing():
    print("test_samesite_missing")
    check("cookie sans SameSite -> vulnérable",
          _samesite_missing("vs_session=abc; Path=/"))
    check("cookie avec SameSite=Lax -> protégé",
          not _samesite_missing("vs_session=abc; Path=/; SameSite=Lax"))
    check("en-tête vide -> non", not _samesite_missing(""))


def test_looks_state_changed():
    print("test_looks_state_changed")
    check("subscribed:true -> changement",
          _looks_state_changed('{"subscribed":true,"email":"x@y.z"}'))
    check("avec espaces -> changement",
          _looks_state_changed('{"subscribed": true}'))
    check("subscribed:false -> pas de changement",
          not _looks_state_changed('{"subscribed":false}'))
    check("réponse quelconque -> non", not _looks_state_changed('{"error":"nope"}'))


def test_base_origin():
    print("test_base_origin")
    check("origine depuis URL",
          _base_origin("https://v.me/api/x?y=1") == "https://v.me")
    check("origine depuis domaine nu", _base_origin("v.me") == "https://v.me")


def test_candidate_endpoints():
    print("test_candidate_endpoints")
    eps = _candidate_endpoints("https://v.me",
                               ["/api/newsletter", "/api/login",
                                "/api/profile?id=1", "/api/products"])
    check("chemins d'action courants inclus",
          all(("https://v.me" + p) in eps for p in COMMON_STATE_PATHS))
    check("endpoint 'profile' inclus", "https://v.me/api/profile" in eps)
    check("endpoint 'products' exclu", "https://v.me/api/products" not in eps)
    check("pas de doublon /api/newsletter",
          eps.count("https://v.me/api/newsletter") == 1)


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — csrf_tester_tool")
    print("=" * 70)
    for t in (test_samesite_missing, test_looks_state_changed,
              test_base_origin, test_candidate_endpoints):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
