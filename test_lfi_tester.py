#!/usr/bin/env python3
"""
Tests PURS du testeur LFI / path traversal (pentagon/tools/lfi_tester_tool.py).

Aucun réseau : on valide la détection de signature /etc/passwd, l'extraction
d'origine et la construction des endpoints candidats. L'attaque réelle est
validée séparément sur VulnShop.
"""

from pentagon.tools.lfi_tester_tool import (
    _is_passwd, _base_origin, _candidate_endpoints, COMMON_FILE_PATHS,
)

results = []


def check(name, condition):
    results.append(condition)
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def test_is_passwd():
    print("test_is_passwd")
    check("ligne root détectée",
          _is_passwd("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"))
    check("HTML quelconque -> non", not _is_passwd("<html>404</html>"))
    check("vide -> non", not _is_passwd(""))


def test_base_origin():
    print("test_base_origin")
    check("origine depuis URL",
          _base_origin("https://v.me/api/x?y=1") == "https://v.me")
    check("origine depuis domaine nu",
          _base_origin("v.me") == "https://v.me")


def test_candidate_endpoints():
    print("test_candidate_endpoints")
    eps = _candidate_endpoints("https://v.me",
                               ["/api/download", "/api/login",
                                "/api/report?id=1", "/api/products"])
    check("chemins courants inclus",
          all(("https://v.me" + p) in eps for p in COMMON_FILE_PATHS))
    check("endpoint 'report' (file-ish) inclus", "https://v.me/api/report" in eps)
    check("endpoint 'login' exclu", "https://v.me/api/login" not in eps)
    check("endpoint 'products' exclu", "https://v.me/api/products" not in eps)
    check("pas de doublon /api/download",
          eps.count("https://v.me/api/download") == 1)


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — lfi_tester_tool")
    print("=" * 70)
    for t in (test_is_passwd, test_base_origin, test_candidate_endpoints):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
