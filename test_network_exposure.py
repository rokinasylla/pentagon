#!/usr/bin/env python3
"""
Tests PURS de l'outil d'analyse d'exposition réseau
(pentagon/tools/network_exposure_tool.py).

Fonction PURE (analyse de données Nmap déjà collectées) → aucun réseau requis.
"""

from pentagon.tools.network_exposure_tool import analyze_network_exposure


results = []


def check(name, condition):
    results.append(condition)
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def _nmap(ports):
    return {"status": "success", "hosts": {"h": {"ports": ports}}}


def _ids(out):
    return {f["id"] for f in out["findings"]}


def test_database_exposed():
    print("test_database_exposed")
    out = analyze_network_exposure(_nmap([
        {"port": 3306, "state": "open", "service": "mysql", "product": "MySQL", "version": "8.0"},
    ]))
    check("MySQL 3306 signalé", "net-exposed-3306" in _ids(out))
    check("sévérité high",
          any(f["severity"] == "high" for f in out["findings"]))


def test_cleartext_and_risky():
    print("test_cleartext_and_risky")
    out = analyze_network_exposure(_nmap([
        {"port": 23, "state": "open", "service": "telnet", "product": "", "version": ""},
    ]))
    check("Telnet service risqué", "net-exposed-23" in _ids(out))
    check("Telnet protocole en clair", "net-cleartext-23" in _ids(out))


def test_web_ports_ignored():
    print("test_web_ports_ignored")
    out = analyze_network_exposure(_nmap([
        {"port": 80, "state": "open", "service": "http", "product": "nginx", "version": ""},
        {"port": 443, "state": "open", "service": "https", "product": "nginx", "version": ""},
    ]))
    check("ports web non signalés", out["findings"] == [])
    check("2 ports comptés", out["open_ports_total"] == 2)


def test_admin_alt_port():
    print("test_admin_alt_port")
    out = analyze_network_exposure(_nmap([
        {"port": 8080, "state": "open", "service": "http-proxy", "product": "", "version": ""},
    ]))
    check("port alt-HTTP signalé", "net-exposed-8080" in _ids(out))
    check("sévérité low (informatif)",
          any(f["severity"] == "low" for f in out["findings"]))


def test_cdn_alt_port_ignored():
    print("test_cdn_alt_port_ignored")
    # Ports alt-HTTP d'un CDN (Cloudflare) → ne doivent PAS être signalés.
    out = analyze_network_exposure(_nmap([
        {"port": 8080, "state": "open", "service": "http-proxy", "product": "cloudflare", "version": ""},
        {"port": 8443, "state": "open", "service": "https-alt", "product": "cloudflare", "version": ""},
    ]))
    check("ports CDN non signalés", out["findings"] == [])
    check("ports quand même comptés", out["open_ports_total"] == 2)


def test_closed_ports_skipped():
    print("test_closed_ports_skipped")
    out = analyze_network_exposure(_nmap([
        {"port": 3306, "state": "closed", "service": "mysql", "product": "", "version": ""},
    ]))
    check("port fermé ignoré", out["findings"] == [])


def test_error_input():
    print("test_error_input")
    out = analyze_network_exposure({"status": "error"})
    check("entrée en erreur -> status error", out["status"] == "error")


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — network_exposure_tool")
    print("=" * 70)
    for t in (test_database_exposed, test_cleartext_and_risky,
              test_web_ports_ignored, test_admin_alt_port,
              test_cdn_alt_port_ignored, test_closed_ports_skipped,
              test_error_input):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
