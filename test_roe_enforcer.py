"""
Test du RoE Enforcer.

Execution : python test_roe_enforcer.py

Valide que le garde-fou autorise les cibles legitimes et refuse
les cibles/actions hors perimetre.
"""

from pentagon.core.roe_enforcer import RoEEnforcer, RoEViolation


def test_case(enforcer, target, action, should_pass):
    """Teste un cas et verifie le resultat attendu."""
    print(f"\n>>> Cible: {target}  |  Action: {action}")
    try:
        enforcer.enforce(target, action)
        result = "✅ AUTORISE"
        passed = should_pass
    except RoEViolation as e:
        result = f"❌ REFUSE — {e}"
        passed = not should_pass

    status = "✓ attendu" if passed else "✗ INATTENDU !"
    print(f"    {result}")
    print(f"    [{status}]")
    return passed


def main():
    print("=" * 70)
    print("PENTAGON — Test du RoE Enforcer")
    print("=" * 70)

    enforcer = RoEEnforcer()

    print(f"\nPolitique chargee : {enforcer.policy['policy_name']}")
    print(f"Cibles autorisees : {enforcer.policy['authorized_targets']}")
    print(f"Actions autorisees : {enforcer.policy['authorized_action_categories']}")
    print(f"Comportement defaut : {enforcer.policy['default_behavior']}")

    print("\n" + "-" * 70)
    print("SCENARIOS DE TEST")
    print("-" * 70)

    results = []

    # Cas 1 : cible autorisee + action passive -> doit passer
    results.append(test_case(enforcer, "techshop-vuln.rokina-sylla.me", "passive", should_pass=True))

    # Cas 2 : cible autorisee (URL complete) + scan actif -> doit passer
    results.append(test_case(enforcer, "https://techshop-vuln.rokina-sylla.me/path", "active_scan", should_pass=True))

    # Cas 3 : backend autorise + scan actif -> doit passer
    results.append(test_case(enforcer, "techshop-backend-cc1t.onrender.com", "active_scan", should_pass=True))

    # Cas 4 : cible autorisee MAIS action exploitation -> doit etre refuse
    results.append(test_case(enforcer, "techshop-vuln.rokina-sylla.me", "exploitation", should_pass=False))

    # Cas 5 : IP partagee Render -> doit etre refuse (hors perimetre)
    results.append(test_case(enforcer, "216.24.57.7", "active_scan", should_pass=False))

    # Cas 6 : cible tierce (Cloudflare) -> doit etre refuse
    results.append(test_case(enforcer, "cloudflare.com", "passive", should_pass=False))

    # Cas 7 : cible totalement externe -> doit etre refuse
    results.append(test_case(enforcer, "google.com", "passive", should_pass=False))

    # Cas 8 : action destructive -> doit etre refuse
    results.append(test_case(enforcer, "techshop-vuln.rokina-sylla.me", "destructive", should_pass=False))

    # Resume d'audit
    print("\n" + "=" * 70)
    print("JOURNAL D'AUDIT")
    print("=" * 70)
    enforcer.print_summary()
    print(f"  Total de decisions journalisees : {len(enforcer.get_audit_log())}")

    # Bilan des tests
    print("\n" + "=" * 70)
    passed = sum(results)
    total = len(results)
    if passed == total:
        print(f"✅ TOUS LES TESTS PASSES ({passed}/{total})")
    else:
        print(f"⚠️  {passed}/{total} tests passes — {total - passed} echec(s)")
    print("=" * 70)


if __name__ == "__main__":
    main()
