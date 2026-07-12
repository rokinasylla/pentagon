"""
Test de la logique pure du backend web (sans lancer de serveur ni campagne).

Vérifie sanitize_actions / compute_plan / summarize_state. Nécessite Flask
installé (import de webapp), donc à lancer sur Kali :

    python test_webapp_logic.py
"""

from webapp import sanitize_actions, compute_plan, summarize_state


def test_sanitize_actions():
    assert sanitize_actions(["exploitation", "passive"]) == ["passive", "exploitation"]
    assert sanitize_actions(["ACTIVE_SCAN"]) == ["active_scan"]      # casse ignorée
    assert sanitize_actions(["destructive", "foo"]) == []            # rejetées
    assert sanitize_actions([]) == []
    print("✓ test_sanitize_actions")


def test_compute_plan():
    plan = compute_plan(["passive", "active_scan"])
    by_phase = {p["phase"]: p["enabled"] for p in plan}
    assert by_phase["OSINT"] is True
    assert by_phase["Scanning"] is True
    assert by_phase["Web App"] is True
    assert by_phase["Exploitation"] is False        # deny-by-default
    print("✓ test_compute_plan")


def test_summarize_state():
    state = {
        "target": "example.com", "campaign_id": "abcd1234",
        "agents_executed": ["OSINT_Agent", "WebApp_Agent"],
        "errors": [],
        "web_app_result": {"analysis": {"overall_risk": "high", "vulnerabilities": [
            {"severity": "high"}, {"severity": "low"}]}},
        "exploitation_result": {"analysis": {"overall_risk": "critical",
            "exploited_vulnerabilities": [{"severity": "critical"}]}},
    }
    s = summarize_state(state)
    assert s["proven_count"] == 1 and s["detected_count"] == 2
    assert s["overall_risk"] == "critical"          # exploitation prioritaire
    assert s["proven_by_severity"] == {"critical": 1}
    assert s["detected_by_severity"].get("high") == 1
    print("✓ test_summarize_state")


def main():
    print("=" * 70)
    print("TEST — Logique du backend web (webapp)")
    print("=" * 70)
    test_sanitize_actions()
    test_compute_plan()
    test_summarize_state()
    print("=" * 70)
    print("✓ Tous les tests passent")
    print("=" * 70)


if __name__ == "__main__":
    main()
