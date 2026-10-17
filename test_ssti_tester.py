#!/usr/bin/env python3
"""
Tests PURS du testeur SSTI (pentagon/tools/ssti_tester_tool.py).

Aucun réseau : on valide la détection d'évaluation (résultat du marqueur),
l'extraction d'origine et la construction des endpoints candidats. L'attaque
réelle est validée séparément sur VulnShop.
"""

from pentagon.tools.ssti_tester_tool import (
    _is_evaluated, _base_origin, _candidate_endpoints,
    COMMON_RENDER_PATHS, SSTI_RESULT, SSTI_EXPR,
)

results = []


def check(name, condition):
    results.append(condition)
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def test_is_evaluated():
    print("test_is_evaluated")
    check("résultat du marqueur détecté",
          _is_evaluated(f"Bonjour {SSTI_RESULT}, bienvenue !"))
    check("littéral réfléchi (non évalué) -> non",
          not _is_evaluated(f"Bonjour {SSTI_EXPR}, bienvenue !"))
    check("page quelconque -> non", not _is_evaluated("<html>accueil</html>"))
    check("vide -> non", not _is_evaluated(""))


def test_base_origin():
    print("test_base_origin")
    check("origine depuis URL",
          _base_origin("https://v.me/api/x?y=1") == "https://v.me")
    check("origine depuis domaine nu", _base_origin("v.me") == "https://v.me")


def test_candidate_endpoints():
    print("test_candidate_endpoints")
    eps = _candidate_endpoints("https://v.me",
                               ["/api/render", "/api/login",
                                "/api/preview?id=1", "/api/products"])
    check("chemins de rendu courants inclus",
          all(("https://v.me" + p) in eps for p in COMMON_RENDER_PATHS))
    check("endpoint 'preview' inclus", "https://v.me/api/preview" in eps)
    check("endpoint 'login' exclu", "https://v.me/api/login" not in eps)
    check("endpoint 'products' exclu", "https://v.me/api/products" not in eps)
    check("pas de doublon /api/render",
          eps.count("https://v.me/api/render") == 1)


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — ssti_tester_tool")
    print("=" * 70)
    for t in (test_is_evaluated, test_base_origin, test_candidate_endpoints):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
