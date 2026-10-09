#!/usr/bin/env python3
"""
Tests PURS de l'outil de sécurité DNS & e-mail
(pentagon/tools/email_dns_security_tool.py).

Ne nécessitent aucun réseau : on valide la normalisation de domaine, la forme
du finding, et la structure normalisée de sortie sur une entrée invalide.
"""

from pentagon.tools.email_dns_security_tool import (
    _normalize_domain, _f, run_email_dns_security,
)

results = []


def check(name, condition):
    results.append(condition)
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def test_normalize_domain():
    print("test_normalize_domain")
    check("URL https -> domaine", _normalize_domain("https://ex.com/a/b") == "ex.com")
    check("URL http -> domaine", _normalize_domain("http://ex.com") == "ex.com")
    check("domaine:port -> domaine", _normalize_domain("ex.com:443") == "ex.com")
    check("casse normalisée", _normalize_domain("ExAmPle.COM") == "example.com")


def test_finding_shape():
    print("test_finding_shape")
    f = _f("x", "titre", "high", "preuve", "RFC")
    check("clés présentes",
          set(f) == {"id", "title", "severity", "evidence", "standard"})
    check("valeurs correctes", f["id"] == "x" and f["severity"] == "high")


def test_invalid_domain():
    print("test_invalid_domain")
    out = run_email_dns_security("")
    check("domaine vide -> status error", out["status"] == "error")
    check("structure normalisée présente",
          {"spf", "dmarc", "dkim", "axfr", "findings"}.issubset(out))


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — email_dns_security_tool")
    print("=" * 70)
    for t in (test_normalize_domain, test_finding_shape, test_invalid_domain):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
