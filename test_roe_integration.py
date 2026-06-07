"""
Test d'intégration du RoE dans l'orchestrateur.
Démontre que le RoE bloque les actions hors périmètre.
Exécution : python test_roe_integration.py
"""

from pentagon.core.orchestrator import Orchestrator
from pentagon.core.roe_enforcer import RoEEnforcer


def main():
    print("=" * 70)
    print("TEST — Politique 'passif seulement' (doit bloquer Scanning + WebApp)")
    print("=" * 70)

    roe_passive_only = RoEEnforcer.from_user_input(
        authorized_targets=["techshop-vuln.rokina-sylla.me"],
        authorized_actions=["passive"],  # SEULEMENT passif
        operator_name="test",
    )

    orchestrator = Orchestrator(roe_enforcer=roe_passive_only)
    state = orchestrator.run_campaign(target="techshop-vuln.rokina-sylla.me")

    print(f"\n>>> Agents exécutés : {state.agents_executed}")
    print(f">>> Blocages : {len(state.errors)}")
    for err in state.errors:
        print(f"    - {err['agent']}: {err['error']}")

    print("\n  ATTENDU : seul OSINT s'exécute. Scanning + WebApp bloqués.")
    print("=" * 70)


if __name__ == "__main__":
    main()
