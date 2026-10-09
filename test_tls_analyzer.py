#!/usr/bin/env python3
"""
Tests PURS de l'outil d'analyse TLS/SSL (pentagon/tools/tls_analyzer_tool.py).

Ne nécessitent aucun réseau : on valide l'extraction hôte/port, le parsing des
dates de certificat, et la logique de détection (certificat expiré, auto-signé)
à partir de structures de certificat synthétiques — comme celles renvoyées par
ssl.getpeercert().
"""

from pentagon.tools.tls_analyzer_tool import (
    _host_port, _parse_cert_datetime, _flatten_name, _analyze_certificate,
    run_tls_analysis,
)

results = []


def check(name, condition):
    results.append(condition)
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def test_host_port():
    print("test_host_port")
    check("URL https", _host_port("https://ex.com/path") == ("ex.com", 443))
    check("domaine nu", _host_port("ex.com") == ("ex.com", 443))
    check("domaine:port", _host_port("ex.com:8443") == ("ex.com", 8443))
    check("URL http -> 443 par defaut", _host_port("http://ex.com")[0] == "ex.com")


def test_parse_date():
    print("test_parse_date")
    d = _parse_cert_datetime("Jun  7 12:00:00 2026 GMT")
    check("date parsee", d is not None and d.year == 2026 and d.month == 6)
    check("date invalide -> None", _parse_cert_datetime("n'importe quoi") is None)


def test_flatten_name():
    print("test_flatten_name")
    seq = ((("commonName", "ex.com"),), (("organizationName", "ACME"),))
    flat = _flatten_name(seq)
    check("commonName extrait", flat.get("commonName") == "ex.com")
    check("organizationName extrait", flat.get("organizationName") == "ACME")


def test_certificate_findings():
    print("test_certificate_findings")
    # Certificat expiré ET auto-signé (issuer == subject).
    cert = {
        "subject": ((("commonName", "ex.com"),),),
        "issuer": ((("commonName", "ex.com"),),),
        "notAfter": "Jan  1 00:00:00 2020 GMT",
    }
    result = {"certificate": {}}
    findings = []
    _analyze_certificate(cert, "ex.com", True, result, findings)
    ids = {f["id"] for f in findings}
    check("certificat expiré détecté", "tls-cert-expired" in ids)
    check("auto-signé détecté", "tls-self-signed" in ids)
    check("sévérité expiré = high",
          any(f["severity"] == "high" for f in findings if f["id"] == "tls-cert-expired"))


def test_invalid_target():
    print("test_invalid_target")
    out = run_tls_analysis("")
    check("cible vide -> status error", out["status"] == "error")
    check("structure normalisée présente",
          set(["findings", "certificate", "negotiated_protocol"]).issubset(out))


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — tls_analyzer_tool")
    print("=" * 70)
    for t in (test_host_port, test_parse_date, test_flatten_name,
              test_certificate_findings, test_invalid_target):
        t()
    print("=" * 70)
    ok = sum(results)
    total = len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
