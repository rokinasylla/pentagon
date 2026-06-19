"""
Test du mode "interactive-scope" : élargissement de périmètre supervisé.

Vérifie, SANS LLM ni réseau, que :
  - le RoE étend dynamiquement le périmètre via add_authorized_target() ;
  - l'orchestrateur ne propose QUE les assets adressables découverts ;
  - le callback opérateur décide asset par asset (deny-by-default) ;
  - le mode statique (authorizer=None) n'élargit jamais le périmètre.

L'orchestrateur est instancié via __new__ (on injecte seulement le RoE),
donc aucun agent/LLM n'est sollicité : les méthodes testées sont pures.

Exécution : python test_interactive_scope.py
"""

from pentagon.core.orchestrator import Orchestrator
from pentagon.core.roe_enforcer import RoEEnforcer
from pentagon.core.state import PentagonState


def _bare_orchestrator(authorized_targets, authorized_actions):
    """Orchestrateur sans __init__ (pas d'agents/LLM), RoE injecté."""
    orch = Orchestrator.__new__(Orchestrator)
    orch.roe = RoEEnforcer.from_user_input(
        authorized_targets, authorized_actions, "test")
    return orch


def test_roe_extension_dynamique():
    roe = RoEEnforcer.from_user_input(["example.com"], ["passive"], "test")
    ip = "203.0.113.5"
    assert roe.check_target(ip)["allowed"] is False          # deny-by-default
    assert roe.add_authorized_target(ip, "asset OSINT") is True
    assert roe.check_target(ip)["allowed"] is True           # désormais permis
    assert roe.add_authorized_target(ip) is False            # déjà présent (dédup)
    logs = [d for d in roe.get_audit_log() if d["check_type"] == "scope_expansion"]
    assert len(logs) == 2                                     # tout est tracé
    print("✓ test_roe_extension_dynamique")


def test_collecte_assets_adressables():
    orch = _bare_orchestrator(["example.com"], ["passive"])
    st = PentagonState(target="example.com")
    st.update_infrastructure("ip_addresses", ["203.0.113.5", "198.51.100.9"])
    st.update_infrastructure("name_servers", ["ns1.example.com"])
    st.update_infrastructure("hosting_provider", "Cloudflare")  # non adressable
    st.update_infrastructure("osint_summary", "blabla")          # non adressable

    assets = orch._collect_discovered_assets(st)
    assert "203.0.113.5" in assets and "198.51.100.9" in assets
    assert "ns1.example.com" in assets
    assert "Cloudflare" not in assets and "blabla" not in assets
    print("✓ test_collecte_assets_adressables")


def test_autorisation_supervisee():
    orch = _bare_orchestrator(["example.com"], ["passive", "active_scan"])
    st = PentagonState(target="example.com")
    st.update_infrastructure("ip_addresses", ["203.0.113.5", "198.51.100.9"])
    st.update_infrastructure("name_servers", ["ns1.example.com"])

    # L'opérateur autorise UNE seule IP, refuse le reste.
    approuves = {"203.0.113.5": True}
    orch._run_scope_authorization(st, lambda asset, infra: approuves.get(asset, False))

    assert orch.roe.check_target("203.0.113.5")["allowed"] is True   # autorisé
    assert orch.roe.check_target("198.51.100.9")["allowed"] is False  # refusé
    assert orch.roe.check_target("ns1.example.com")["allowed"] is False
    events = [e["event"] for e in st.execution_log]
    assert "scope_expanded" in events and "scope_denied" in events
    print("✓ test_autorisation_supervisee")


def test_mode_statique_n_elargit_jamais():
    orch = _bare_orchestrator(["example.com"], ["passive"])
    st = PentagonState(target="example.com")
    st.update_infrastructure("ip_addresses", ["10.0.0.1"])

    orch._run_scope_authorization(st, None)   # authorizer=None → statique

    assert orch.roe.check_target("10.0.0.1")["allowed"] is False
    # Aucun événement d'élargissement émis.
    assert not any(e["event"].startswith("scope_") for e in st.execution_log)
    print("✓ test_mode_statique_n_elargit_jamais")


def test_callback_qui_echoue_ne_elargit_pas():
    """Robustesse : si le dialogue plante, le périmètre ne change pas."""
    orch = _bare_orchestrator(["example.com"], ["passive"])
    st = PentagonState(target="example.com")
    st.update_infrastructure("ip_addresses", ["203.0.113.5"])

    def authorizer_qui_plante(asset, infra):
        raise RuntimeError("dialogue interrompu")

    orch._run_scope_authorization(st, authorizer_qui_plante)
    assert orch.roe.check_target("203.0.113.5")["allowed"] is False
    assert any(e["agent"] == "RoE" for e in st.errors)
    print("✓ test_callback_qui_echoue_ne_elargit_pas")


def main():
    print("=" * 70)
    print("TEST — Élargissement de périmètre supervisé (interactive-scope)")
    print("=" * 70)
    test_roe_extension_dynamique()
    test_collecte_assets_adressables()
    test_autorisation_supervisee()
    test_mode_statique_n_elargit_jamais()
    test_callback_qui_echoue_ne_elargit_pas()
    print("=" * 70)
    print("✓ Tous les tests passent")
    print("=" * 70)


if __name__ == "__main__":
    main()
