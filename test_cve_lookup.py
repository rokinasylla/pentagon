#!/usr/bin/env python3
"""
Tests PURS de l'outil de corrélation CVE (pentagon/tools/cve_lookup_tool.py).

Aucun réseau : on teste l'extraction des composants, le parsing d'une réponse
NVD synthétique et le mapping CVSS. L'appel réseau réel (_query_nvd) est validé
séparément sur la VM.
"""

from pentagon.tools.cve_lookup_tool import (
    extract_products, _parse_nvd_response, _cvss_severity, _extract_cvss,
    run_cve_analysis,
)

results = []


def check(name, condition):
    results.append(condition)
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def test_extract_products():
    print("test_extract_products")
    ww = {"technologies": [
        {"name": "nginx", "values": ["nginx/1.18.0"]},
        {"name": "HTML5", "values": []},          # sans version -> ignoré
        {"name": "jQuery", "values": ["3.5.1"]},
    ]}
    nm = {"status": "success", "hosts": {"h": {"ports": [
        {"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "7.2"},
        {"port": 80, "state": "open", "service": "http", "product": "", "version": ""},  # sans version
    ]}}}
    prods = extract_products(ww, nm)
    names = {p[0].lower() for p in prods}
    check("nginx extrait", ("nginx", "1.18.0") in prods)
    check("jQuery extrait", ("jQuery", "3.5.1") in prods)
    check("OpenSSH extrait", ("OpenSSH", "7.2") in prods)
    check("HTML5 (sans version) ignoré", "html5" not in names)


def test_cvss_severity():
    print("test_cvss_severity")
    check("9.8 -> critical", _cvss_severity(9.8) == "critical")
    check("7.5 -> high", _cvss_severity(7.5) == "high")
    check("5.0 -> medium", _cvss_severity(5.0) == "medium")
    check("2.0 -> low", _cvss_severity(2.0) == "low")


def test_extract_cvss():
    print("test_extract_cvss")
    m = {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}
    score, sev = _extract_cvss(m)
    check("score V31 extrait", score == 7.5 and sev == "HIGH")
    check("métriques vides -> 0", _extract_cvss({}) == (0.0, ""))


def test_parse_nvd_response():
    print("test_parse_nvd_response")
    nvd = {"vulnerabilities": [
        {"cve": {"id": "CVE-A", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.3}}]}}},
        {"cve": {"id": "CVE-B", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1}}]}}},
    ]}
    f = _parse_nvd_response(nvd, "OpenSSH", "7.2")
    check("finding produit", f is not None and "OpenSSH 7.2" in f["title"])
    check("sévérité = max (critical)", f["severity"] == "critical")
    check("CVE la plus grave en tête", f["cves"][0]["id"] == "CVE-B")
    check("réponse vide -> None",
          _parse_nvd_response({"vulnerabilities": []}, "x", "1.0") is None)


def test_no_components():
    print("test_no_components")
    out = run_cve_analysis(whatweb_data={"technologies": []}, nmap_data=None)
    check("aucun composant -> success + note",
          out["status"] == "success" and bool(out["note"]))
    check("findings vides", out["findings"] == [])


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — cve_lookup_tool")
    print("=" * 70)
    for t in (test_extract_products, test_cvss_severity, test_extract_cvss,
              test_parse_nvd_response, test_no_components):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
