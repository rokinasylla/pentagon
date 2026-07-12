"""
Test du constructeur de rapport (couche pure, sans reportlab ni réseau).

Vérifie que build_report() normalise et agrège correctement un JSON de
campagne : findings unifiés (prouvés d'abord), comptes de sévérité, couverture
OWASP, risque global, reconnaissance et audit.

Exécution : python test_report_builder.py
"""

from pentagon.tools.report_builder import build_report, SEVERITY_LABELS


def _sample_campaign() -> dict:
    """Campagne synthétique représentative (schéma réel des agents)."""
    return {
        "campaign_id": "11d481ce-a2d7-46d1-8457-5b441cca143d",
        "target": "techshop-vuln.rokina-sylla.me",
        "started_at": "2026-07-12T19:30:00+00:00",
        "ended_at": "2026-07-12T19:38:22+00:00",
        "agents_executed": ["OSINT_Agent", "Scanning_Agent",
                            "WebApp_Agent", "Exploitation_Agent"],
        "discovered_infrastructure": {"hosting_provider": "Cloudflare"},
        "osint_result": {"executive_summary": "Cible derrière Cloudflare."},
        "scanning_result": {"analysis": {"key_findings": [
            {"finding": "Ports 80/443 ouverts"}]}},
        "web_app_result": {
            "executive_summary": "Backend découplé, données exposées.",
            "analysis": {
                "overall_risk": "critical",
                "vulnerabilities": [
                    {"title": "Données sensibles exposées", "severity": "high",
                     "owasp_top10": "A02:2021 Cryptographic Failures",
                     "cwe": "CWE-359", "affected_endpoint": "/api/users",
                     "description": "PII exposée", "evidence": "hash MD5 présent",
                     "remediation": "Chiffrer", "confidence": 0.9},
                    {"title": "Header manquant", "severity": "low",
                     "owasp_top10": "A05:2021 Security Misconfiguration",
                     "confidence": 0.7},
                ],
            },
        },
        "exploitation_result": {
            "executive_summary": "Auth par défaut, IDOR, SQLi prouvés.",
            "analysis": {
                "overall_risk": "critical",
                "exploited_vulnerabilities": [
                    {"title": "Identifiants par défaut", "severity": "critical",
                     "owasp_top10": "A07:2021 Auth Failures", "cwe": "CWE-1392",
                     "mitre": "T1110.001", "affected_endpoint": "/api/auth/login",
                     "proof": "token admin récupéré", "impact": "prise de contrôle",
                     "remediation": "Forcer un mot de passe fort", "confidence": 1.0},
                    {"title": "IDOR horizontal", "severity": "high",
                     "owasp_top10": "A01:2021 Broken Access Control",
                     "affected_endpoint": "/api/users/{id}",
                     "proof": "accès aux objets d'autrui", "confidence": 0.95},
                ],
                "attempted_but_not_confirmed": ["XSS stocké non confirmé via API"],
            },
        },
        "execution_log": [{"timestamp": "2026-07-12T19:30:00+00:00",
                          "agent": "orchestrator", "event": "phase_start",
                          "details": "OSINT"}],
        "errors": [],
    }


def test_findings_unifies_et_ordonnes():
    m = build_report(_sample_campaign(), operator="rokhaya")
    assert len(m.findings) == 4            # 2 prouvées + 2 détectées
    assert m.proven_count == 2 and m.detected_count == 2
    # Les prouvées viennent avant les détectées.
    assert m.findings[0].proven and m.findings[1].proven
    assert not m.findings[2].proven and not m.findings[3].proven
    # Dans les prouvées, critical avant high.
    assert m.findings[0].severity == "critical"
    assert m.findings[1].severity == "high"
    print("✓ test_findings_unifies_et_ordonnes")


def test_mapping_champs_exploitation():
    m = build_report(_sample_campaign())
    f = m.findings[0]                       # identifiants par défaut
    assert f.evidence == "token admin récupéré"      # proof -> evidence
    assert f.description == "prise de contrôle"      # impact -> description
    assert f.mitre == "T1110.001"
    print("✓ test_mapping_champs_exploitation")


def test_comptes_severite():
    m = build_report(_sample_campaign())
    assert m.severity_counts["critical"] == 1
    assert m.severity_counts["high"] == 2
    assert m.severity_counts["low"] == 1
    assert set(m.severity_counts.keys()) == set(SEVERITY_LABELS)
    print("✓ test_comptes_severite")


def test_risque_global_et_owasp():
    m = build_report(_sample_campaign())
    assert m.overall_risk == "critical"
    # 4 catégories OWASP distinctes (A01, A02, A05, A07), triées.
    assert len(m.owasp_coverage) == 4
    assert m.owasp_coverage[0].startswith("A01")
    print("✓ test_risque_global_et_owasp")


def test_recon_et_audit():
    m = build_report(_sample_campaign())
    assert "Cloudflare" in m.recon_osint_summary
    assert len(m.recon_scanning_findings) == 1
    assert m.attempted_not_confirmed == ["XSS stocké non confirmé via API"]
    assert "Exploitation" in m.exec_summaries
    assert len(m.execution_log) == 1
    print("✓ test_recon_et_audit")


def test_campagne_vide_ne_plante_pas():
    m = build_report({"target": "x", "agents_executed": []})
    assert m.findings == []
    assert m.overall_risk == "info"
    assert m.severity_counts["critical"] == 0
    print("✓ test_campagne_vide_ne_plante_pas")


def main():
    print("=" * 70)
    print("TEST — Constructeur de rapport (report_builder)")
    print("=" * 70)
    test_findings_unifies_et_ordonnes()
    test_mapping_champs_exploitation()
    test_comptes_severite()
    test_risque_global_et_owasp()
    test_recon_et_audit()
    test_campagne_vide_ne_plante_pas()
    print("=" * 70)
    print("✓ Tous les tests passent")
    print("=" * 70)


if __name__ == "__main__":
    main()
