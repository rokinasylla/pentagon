#!/usr/bin/env python3
"""
Tests PURS du dispatcher de commandes (pentagon/core/command_dispatcher.py).

Aucun réseau, aucun LLM : on valide l'analyse des formes slash ET naturelles,
l'extraction des arguments (numéro de faille, cible de périmètre), la garde RoE
deny-by-default, le routage vers les handlers injectés et la gestion d'erreur.
"""

from pentagon.core.command_dispatcher import (
    parse_command, CommandDispatcher, Command,
    SCAN, EXPLOIT, CONFIRM, AUDIT, REPORT, SCOPE, STOP, HELP, UNKNOWN,
)

results = []


def check(name, condition):
    results.append(bool(condition))
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


ALLOW = lambda cat, tgt: {"allowed": True, "reason": "autorisé (test)"}
DENY = lambda cat, tgt: {"allowed": False, "reason": "hors périmètre (test)"}


# ----------------------------- Parsing slash -----------------------------
def test_parse_slash():
    print("test_parse_slash")
    check("/scan -> scan", parse_command("/scan").action == SCAN)
    check("/audit -> audit", parse_command("/audit").action == AUDIT)
    check("/report -> report", parse_command("/report").action == REPORT)
    check("/stop -> stop", parse_command("/stop").action == STOP)
    check("/help -> help", parse_command("/help").action == HELP)
    check("casse ignorée (/SCAN)", parse_command("/SCAN").action == SCAN)
    check("alias /exploiter -> exploit",
          parse_command("/exploiter 2").action == EXPLOIT)
    check("slash inconnu -> unknown", parse_command("/foobar").action == UNKNOWN)
    check("slash vide -> unknown", parse_command("/").action == UNKNOWN)


def test_parse_slash_index_and_arg():
    print("test_parse_slash_index_and_arg")
    c = parse_command("/exploit 3")
    check("/exploit 3 -> action exploit", c.action == EXPLOIT)
    check("/exploit 3 -> index 3", c.index == 3)
    check("/confirm 12 -> index 12", parse_command("/confirm 12").index == 12)
    check("/exploit sans numéro -> index None",
          parse_command("/exploit").index is None)
    s = parse_command("/scope exemple.com")
    check("/scope -> action scope", s.action == SCOPE)
    check("/scope -> arg cible", s.arg == "exemple.com")


# --------------------------- Parsing naturel -----------------------------
def test_parse_natural():
    print("test_parse_natural")
    check("« lance un scan » -> scan",
          parse_command("lance un scan complet").action == SCAN)
    check("« exploite la faille 3 » -> exploit",
          parse_command("exploite la faille 3").action == EXPLOIT)
    check("« exploite la faille 3 » -> index 3",
          parse_command("exploite la faille 3").index == 3)
    check("« confirme la 2 » -> confirm",
          parse_command("confirme la 2").action == CONFIRM)
    check("« confirme la 2 » -> index 2",
          parse_command("confirme la 2").index == 2)
    check("« génère le rapport » -> report",
          parse_command("génère le rapport").action == REPORT)
    check("« montre l'audit » -> audit",
          parse_command("montre l'audit de durcissement").action == AUDIT)
    check("« arrête tout » -> stop",
          parse_command("arrête tout maintenant").action == STOP)
    check("« quelles commandes ? » -> help",
          parse_command("quelles commandes sont disponibles ?").action == HELP)
    check("texte hors sujet -> unknown",
          parse_command("bonjour, il fait beau").action == UNKNOWN)
    check("vide -> unknown", parse_command("   ").action == UNKNOWN)


def test_parse_natural_scope_target():
    print("test_parse_natural_scope_target")
    c = parse_command("ajoute la cible staging.exemple.com au périmètre")
    check("action scope", c.action == SCOPE)
    check("cible extraite", "staging.exemple.com" in c.arg)
    check("mots d'intention retirés",
          "ajoute" not in c.arg.lower() and "perimetre" not in
          _no_accents(c.arg.lower()))


def test_parse_natural_earliest_wins():
    print("test_parse_natural_earliest_wins")
    # « confirme » apparaît avant « exploite » -> confirm gagne
    check("mot-clé le plus tôt gagne",
          parse_command("confirme puis exploite la 4").action == CONFIRM)


def _no_accents(s):
    from pentagon.core.command_dispatcher import _strip_accents
    return _strip_accents(s)


# ------------------------------- Dispatch --------------------------------
def test_dispatch_unknown_and_help():
    print("test_dispatch_unknown_and_help")
    d = CommandDispatcher(handlers={}, roe_check=ALLOW)
    check("inconnu -> status unknown",
          d.dispatch("blabla").get("status") == "unknown")
    out = d.dispatch("/help")
    check("help -> status help", out["status"] == "help")
    check("help -> texte fourni", "/scan" in out["help"])


def test_dispatch_needs_index_and_arg():
    print("test_dispatch_needs_index_and_arg")
    d = CommandDispatcher(handlers={EXPLOIT: lambda c: "x", SCOPE: lambda c: "y"},
                          roe_check=ALLOW)
    check("/exploit sans numéro -> needs_index",
          d.dispatch("/exploit").get("status") == "needs_index")
    check("/scope sans cible -> needs_arg",
          d.dispatch("/scope").get("status") == "needs_arg")


def test_dispatch_roe_deny_by_default():
    print("test_dispatch_roe_deny_by_default")
    # Sans roe_check injecté : deny-by-default sur les actions offensives.
    d = CommandDispatcher(handlers={EXPLOIT: lambda c: "ne doit pas tourner"})
    out = d.dispatch("/exploit 1")
    check("exploit refusé par défaut", out["status"] == "denied")


def test_dispatch_roe_deny_injected():
    print("test_dispatch_roe_deny_injected")
    ran = []
    d = CommandDispatcher(handlers={SCAN: lambda c: ran.append(True)},
                          roe_check=DENY)
    out = d.dispatch("/scan")
    check("scan refusé", out["status"] == "denied")
    check("raison propagée", "hors périmètre" in out["reason"])
    check("handler NON exécuté", len(ran) == 0)


def test_dispatch_roe_category_passed():
    print("test_dispatch_roe_category_passed")
    seen = []

    def spy(cat, tgt):
        seen.append((cat, tgt))
        return {"allowed": True}

    d = CommandDispatcher(handlers={EXPLOIT: lambda c: "ok", SCAN: lambda c: "ok"},
                          roe_check=spy, target="exemple.com")
    d.dispatch("/exploit 1")
    d.dispatch("/scan")
    check("exploit -> catégorie exploitation", seen[0][0] == "exploitation")
    check("scan -> catégorie active_scan", seen[1][0] == "active_scan")
    check("cible transmise au RoE", seen[0][1] == "exemple.com")


def test_dispatch_no_roe_for_read_actions():
    print("test_dispatch_no_roe_for_read_actions")
    # audit/report/stop ne touchent pas la cible : pas de contrôle offensif,
    # ils passent même avec un RoE qui refuse tout.
    d = CommandDispatcher(
        handlers={AUDIT: lambda c: "audit", REPORT: lambda c: "rapport",
                  STOP: lambda c: "stop"},
        roe_check=DENY)
    check("audit passe sans RoE offensif", d.dispatch("/audit")["status"] == "ok")
    check("report passe", d.dispatch("/report")["status"] == "ok")
    check("stop passe", d.dispatch("/stop")["status"] == "ok")


def test_dispatch_routes_to_handler():
    print("test_dispatch_routes_to_handler")
    calls = []
    d = CommandDispatcher(
        handlers={EXPLOIT: lambda c: {"exploited": c.index}},
        roe_check=ALLOW)
    out = d.dispatch("exploite la faille 5")
    check("status ok", out["status"] == "ok")
    check("action exploit", out["action"] == EXPLOIT)
    check("index transmis au handler", out["result"] == {"exploited": 5})
    check("commande conservée", isinstance(out["command"], Command))


def test_dispatch_unsupported_and_error():
    print("test_dispatch_unsupported_and_error")
    d = CommandDispatcher(handlers={}, roe_check=ALLOW)
    check("action sans handler -> unsupported",
          d.dispatch("/audit")["status"] == "unsupported")

    def boom(c):
        raise ValueError("casse")

    d2 = CommandDispatcher(handlers={AUDIT: boom}, roe_check=ALLOW)
    out = d2.dispatch("/audit")
    check("handler qui lève -> handler_error", out["status"] == "handler_error")
    check("type d'erreur rapporté", "ValueError" in out["reason"])


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — core/command_dispatcher")
    print("=" * 70)
    for t in (test_parse_slash, test_parse_slash_index_and_arg,
              test_parse_natural, test_parse_natural_scope_target,
              test_parse_natural_earliest_wins,
              test_dispatch_unknown_and_help, test_dispatch_needs_index_and_arg,
              test_dispatch_roe_deny_by_default, test_dispatch_roe_deny_injected,
              test_dispatch_roe_category_passed,
              test_dispatch_no_roe_for_read_actions,
              test_dispatch_routes_to_handler,
              test_dispatch_unsupported_and_error):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
