#!/usr/bin/env python3
"""
PENTAGON — Interface en ligne de commande (CLI opérateur).

Point d'entrée unique pour lancer une campagne de pentest automatisée
SANS éditer le code ni le fichier de politique. L'opérateur définit ici :
  - la (les) cible(s) du périmètre autorisé ;
  - les catégories d'action permises (Rules of Engagement) ;
  - son identité (traçabilité / audit) ;
  - le profil de scan.

Cette CLI matérialise un principe central de PENTAGON : la SÉPARATION entre
le code générique (pentagon/) et la configuration spécifique à la mission
(saisie par l'opérateur). Elle s'appuie sur RoEEnforcer.from_user_input()
pour construire dynamiquement la politique, puis sur l'Orchestrator pour
dérouler la chaîne d'agents sous le contrôle du RoE.

Garde-fou rappelé à chaque lancement : DENY BY DEFAULT. Toute catégorie non
sélectionnée explicitement est refusée — en particulier la phase Exploitation
(offensive), qui exige un choix conscient et une confirmation.

Deux modes :
  - Interactif (aucun argument requis) : la CLI pose les questions.
  - Non-interactif (flags) : pour scripter / reproduire une campagne.

Exemples :
  python pentagon.py
  python pentagon.py --target techshop-vuln.rokina-sylla.me \\
      --extra-target techshop-backend-cc1t.onrender.com \\
      --actions passive,active_scan,exploitation \\
      --operator rokhaya --yes
"""

import argparse
import sys
from collections import Counter

# NB : l'import de l'Orchestrator (qui tire la stack LLM) est DIFFÉRÉ dans
# run_mission(). Cela permet d'utiliser --help, la saisie RoE, le récap et la
# confirmation en stdlib pur, sans dépendance réseau/LLM (testable hors-ligne).
from pentagon.core.roe_enforcer import RoEEnforcer, ACTION_CATEGORIES


# Catégories proposables à l'opérateur, par risque croissant.
# 'destructive' est volontairement EXCLUE : décision conceptuelle de PENTAGON
# (« détecter en prouvant, jamais ravager »). Elle reste définie dans le RoE
# mais n'est jamais offerte via cette interface.
SELECTABLE_CATEGORIES = ["passive", "active_scan", "exploitation"]

DEFAULT_SCAN_PROFILE = "web_focused"


# ───────────────────────────── Saisie interactive ──────────────────────────

def _prompt(text: str, default: str = "") -> str:
    """Pose une question avec valeur par défaut affichée entre crochets."""
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{text}{suffix} : ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nAnnulé par l'opérateur.")
        sys.exit(130)
    return answer or default


def _prompt_targets() -> list[str]:
    """Demande la cible principale puis les cibles additionnelles."""
    primary = ""
    while not primary:
        primary = _prompt("Cible principale (domaine ou URL)")
        if not primary:
            print("  ⚠️  Une cible est obligatoire (deny-by-default : sans périmètre, rien ne tourne).")

    extra_raw = _prompt(
        "Cibles additionnelles du périmètre (séparées par des virgules, optionnel)"
    )
    extras = [t.strip() for t in extra_raw.split(",") if t.strip()]

    # On déduplique en conservant l'ordre (primary d'abord)
    targets = [primary]
    for t in extras:
        if t not in targets:
            targets.append(t)
    return targets


def _prompt_actions() -> list[str]:
    """
    Demande les catégories d'action autorisées (RoE).

    Affiche le niveau de risque de chacune et rappelle le deny-by-default.
    Accepte soit des numéros (1,2,3) soit des noms (passive,active_scan).
    """
    print("\nCatégories d'action autorisées (Rules of Engagement) :")
    for i, cat in enumerate(SELECTABLE_CATEGORIES, start=1):
        print(f"   [{i}] {cat:<13} — {ACTION_CATEGORIES[cat]}")
    print("   (la catégorie 'destructive' n'est jamais proposée : hors charte éthique)")
    print("   Rappel : toute catégorie NON sélectionnée est refusée (deny-by-default).")

    while True:
        raw = _prompt("Votre choix (ex: 1,2 ou passive,active_scan)", "1,2")
        actions = _parse_actions(raw)
        if actions:
            return actions
        print("  ⚠️  Choix invalide. Utilisez des numéros (1-3) ou des noms valides.")


def _parse_actions(raw: str) -> list[str]:
    """
    Convertit une saisie (numéros et/ou noms) en liste de catégories valides.

    Retourne [] si rien de valide n'est reconnu (pour redemander).
    'destructive' est explicitement rejetée même si saisie au nom.
    """
    actions: list[str] = []
    for token in raw.replace(";", ",").split(","):
        token = token.strip().lower()
        if not token:
            continue
        if token.isdigit():
            idx = int(token) - 1
            if 0 <= idx < len(SELECTABLE_CATEGORIES):
                cat = SELECTABLE_CATEGORIES[idx]
            else:
                continue
        elif token in SELECTABLE_CATEGORIES:
            cat = token
        elif token == "destructive":
            print("  ⛔ 'destructive' refusée : PENTAGON prouve sans ravager.")
            continue
        else:
            continue
        if cat not in actions:
            actions.append(cat)
    return actions


# ──────────────────────────── Récap & confirmation ─────────────────────────

def _print_plan(targets: list[str], actions: list[str], operator: str,
                scan_profile: str, interactive_scope: bool = False) -> None:
    """Affiche le récapitulatif de mission avant lancement."""
    print("\n" + "=" * 70)
    print("RÉCAPITULATIF DE LA MISSION (à valider)")
    print("=" * 70)
    print(f"  Opérateur        : {operator}")
    print(f"  Cible principale : {targets[0]}")
    if len(targets) > 1:
        print(f"  Périmètre étendu : {', '.join(targets[1:])}")
    print(f"  Profil de scan   : {scan_profile}")
    print(f"  Actions RoE      : {', '.join(actions)}")
    mode_scope = "interactif (supervisé après OSINT)" if interactive_scope else "statique (figé)"
    print(f"  Périmètre        : {mode_scope}")

    # Phases qui s'exécuteront vs sautées, dérivées des catégories autorisées.
    phase_category = [
        ("OSINT", "passive"),
        ("Scanning", "active_scan"),
        ("Web App", "active_scan"),
        ("Exploitation", "exploitation"),
    ]
    print("\n  Phases prévues (deny-by-default) :")
    for phase, cat in phase_category:
        mark = "✓ exécutée" if cat in actions else "✗ sautée (RoE)"
        print(f"     • {phase:<13} [{cat}] → {mark}")

    if "exploitation" in actions:
        print("\n  ⚠️  La phase OFFENSIVE (exploitation) est ACTIVÉE.")
        print("      PENTAGON s'arrête à la PREUVE de la faille — aucun dommage.")
    print("=" * 70)


def _confirm(auto_yes: bool) -> bool:
    """Demande une confirmation explicite (human-in-the-loop)."""
    if auto_yes:
        print("\n[--yes] Confirmation automatique.")
        return True
    answer = _prompt("\nLancer la campagne ? (o/N)", "N").lower()
    return answer in ("o", "oui", "y", "yes")


def _make_scope_authorizer(auto_yes: bool):
    """
    Construit le callback d'élargissement de périmètre (mode interactif).

    Injecté dans l'orchestrateur : il est appelé pour chaque asset découvert
    hors périmètre. Rappelle la responsabilité légale avant chaque décision.
    En mode --yes (aucun humain présent), refuse systématiquement
    l'élargissement pour préserver le deny-by-default.
    """
    def authorizer(asset: str, infrastructure: dict) -> bool:
        print(f"\n  🔎 Asset découvert HORS périmètre : {asset}")
        print( "     ⚖️  Rappel : l'autoriser n'est légal que si tu as réellement")
        print( "         le droit de tester cet asset (accord du propriétaire).")
        if auto_yes:
            print("     [--yes] Élargissement refusé d'office (deny-by-default préservé).")
            return False
        answer = _prompt("     Ajouter au périmètre autorisé ? (o/N)", "N").lower()
        return answer in ("o", "oui", "y", "yes")

    return authorizer


# ──────────────────────────── Synthèse de campagne ─────────────────────────

def _print_summary(state, output_file: str | None) -> None:
    """Affiche la synthèse finale d'une campagne (réutilisée par tout mode)."""
    print("\n" + "=" * 70)
    print("SYNTHÈSE DE LA CAMPAGNE")
    print("=" * 70)
    print(f"  Campaign ID      : {state.campaign_id}")
    print(f"  Cible            : {state.target}")
    print(f"  Agents exécutés  : {', '.join(state.agents_executed) or '(aucun)'}")
    print(f"  Erreurs          : {len(state.errors)}")

    if state.web_app_result:
        vulns = state.web_app_result.get("analysis", {}).get("vulnerabilities", [])
        if vulns:
            counts = Counter(v.get("severity", "info") for v in vulns)
            print(f"\n  📊 Vulnérabilités (Web App) : {dict(counts)}")

    if state.exploitation_result:
        exploited = state.exploitation_result.get("analysis", {}).get(
            "exploited_vulnerabilities", [])
        if exploited:
            counts = Counter(v.get("severity", "info") for v in exploited)
            print(f"  💥 Vulnérabilités PROUVÉES  : {dict(counts)}")

    if output_file:
        print(f"\n  📂 Campagne sauvegardée : {output_file}")
    print("=" * 70)


# ───────────────────────────────── Pipeline ────────────────────────────────

def run_mission(targets: list[str], actions: list[str], operator: str,
                scan_profile: str, output_dir: str, save: bool,
                scope_authorizer=None):
    """
    Construit le RoE depuis la saisie opérateur puis lance la campagne.

    Le code générique (Orchestrator/agents) ne connaît aucune cible : tout
    vient d'ici. C'est la séparation code/config en action.
    """
    # Import différé : ne charge la stack LLM qu'au moment du lancement réel.
    from pentagon.core.orchestrator import Orchestrator

    roe = RoEEnforcer.from_user_input(
        authorized_targets=targets,
        authorized_actions=actions,
        operator_name=operator,
    )

    orchestrator = Orchestrator(roe_enforcer=roe)
    state = orchestrator.run_campaign(
        target=targets[0],
        scan_profile=scan_profile,
        scope_authorizer=scope_authorizer,
    )

    output_file = orchestrator.save_campaign(state, output_dir=output_dir) if save else None
    _print_summary(state, output_file)
    return state


# ───────────────────────────────── Arguments ───────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pentagon",
        description="PENTAGON — campagne de pentest multi-agent sous Rules of Engagement.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target", help="Cible principale (domaine ou URL).")
    p.add_argument("--extra-target", action="append", default=[],
                   help="Cible additionnelle du périmètre (répétable).")
    p.add_argument("--actions",
                   help="Catégories RoE séparées par virgule "
                        "(passive,active_scan,exploitation).")
    p.add_argument("--operator", default="anonyme",
                   help="Nom de l'opérateur (traçabilité/audit).")
    p.add_argument("--scan-profile", default=DEFAULT_SCAN_PROFILE,
                   help=f"Profil de scan Nmap (défaut: {DEFAULT_SCAN_PROFILE}).")
    p.add_argument("--output-dir", default="results",
                   help="Dossier de sauvegarde du JSON (défaut: results).")
    p.add_argument("--no-save", action="store_true",
                   help="Ne pas sauvegarder le JSON de campagne.")
    p.add_argument("--interactive-scope", action="store_true",
                   help="Après l'OSINT, proposer d'autoriser les assets "
                        "découverts (élargissement de périmètre supervisé).")
    p.add_argument("--yes", "-y", action="store_true",
                   help="Confirmer automatiquement (mode non-interactif).")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    print("=" * 70)
    print("PENTAGON — Interface de campagne (multi-agent, gouvernée par le RoE)")
    print("=" * 70)

    # Mode non-interactif si la cible ET les actions sont fournies en flags ;
    # sinon, on complète par des questions interactives.
    if args.target:
        targets = [args.target]
        for t in args.extra_target:
            if t not in targets:
                targets.append(t)
    else:
        targets = _prompt_targets()

    if args.actions:
        actions = _parse_actions(args.actions)
        if not actions:
            print("Aucune catégorie d'action valide fournie. Abandon.")
            return 2
    else:
        actions = _prompt_actions()

    operator = args.operator
    if operator == "anonyme" and not args.target:
        operator = _prompt("Nom de l'opérateur (traçabilité)", "anonyme")

    scan_profile = args.scan_profile

    _print_plan(targets, actions, operator, scan_profile, args.interactive_scope)

    if not _confirm(args.yes):
        print("Campagne annulée. Aucune action menée.")
        return 0

    scope_authorizer = _make_scope_authorizer(args.yes) if args.interactive_scope else None

    try:
        run_mission(
            targets=targets,
            actions=actions,
            operator=operator,
            scan_profile=scan_profile,
            output_dir=args.output_dir,
            save=not args.no_save,
            scope_authorizer=scope_authorizer,
        )
    except Exception as e:
        print(f"\n❌ Échec de la campagne : {type(e).__name__}: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
