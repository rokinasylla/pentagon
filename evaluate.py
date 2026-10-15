#!/usr/bin/env python3
"""
PENTAGON — Évaluation qualité d'une campagne (Lot 6).

Compare le JSON d'une campagne à une vérité terrain et produit des métriques
(précision/rappel/F1) + un rapport qualité Markdown & JSON, exploitable pour la
soutenance (chiffrage de la limite « absence de métriques formelles »).

Exemples :
    python evaluate.py results/campaign_vulnshop....json
    python evaluate.py results/campaign_x.json --ground-truth benchmark/vulnshop_ground_truth.json
    python evaluate.py results/campaign_x.json --out benchmark/

Tout est stdlib pur (aucun LLM, aucun réseau) → exécutable partout, y compris
hors ligne.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from pentagon.tools.evaluation_tool import score_campaign

_DEFAULT_GT = os.path.join("benchmark", "vulnshop_ground_truth.json")


def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _fmt_pct(x: float) -> str:
    return f"{x * 100:.1f} %"


def render_markdown(res: dict) -> str:
    """Rapport qualité lisible (Markdown) à partir du résultat de scoring."""
    c, m = res["counts"], res["metrics"]
    lines = [
        f"# Rapport qualité PENTAGON — {res.get('benchmark', '')}",
        "",
        f"- **Cible** : {res.get('target', '')}",
        f"- **Campagne** : {res.get('campaign_id', '')}",
        f"- **Généré le** : {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
        "## Métriques",
        "",
        "| Métrique | Valeur |",
        "|---|---|",
        f"| **Rappel** (couverture de la vérité terrain) | **{_fmt_pct(m['recall'])}** |",
        f"| Précision (borne basse) | {_fmt_pct(m['precision_lower_bound'])} |",
        f"| F1 (borne basse) | {_fmt_pct(m['f1_lower_bound'])} |",
        "",
        "| Décompte | n |",
        "|---|---|",
        f"| Items de vérité terrain | {c['ground_truth_items']} |",
        f"| Findings de la campagne | {c['findings_total']} |",
        f"| Vrais positifs (TP) | {c['true_positives']} |",
        f"| Faux négatifs (FN, manqués) | {c['false_negatives']} |",
        f"| Findings non catalogués (FP candidats) | {c['unmatched_findings']} |",
        "",
        "> La **précision** est une **borne basse** : tout finding non présent au "
        "catalogue est compté comme faux positif, alors que certains peuvent être "
        "de vraies failles hors périmètre (à qualifier manuellement).",
        "",
        "## Couverture par item (vérité terrain)",
        "",
        "| Item | OWASP | Attendu | Trouvé | Profondeur OK | Sources |",
        "|---|---|---|---|---|---|",
    ]
    for pi in res["per_item"]:
        found = "✅" if pi["found"] else "❌"
        depth = "✅" if pi["depth_ok"] else ("—" if not pi["found"] else "⚠️")
        srcs = ", ".join(pi["sources"]) or "—"
        lines.append(f"| {pi['title']} | {pi['owasp']} | {pi['expected']} | "
                     f"{found} | {depth} | {srcs} |")

    lines += ["", "## Rappel par catégorie OWASP", "",
              "| OWASP | Trouvés / Total |", "|---|---|"]
    for cat in sorted(res["recall_by_owasp"]):
        d = res["recall_by_owasp"][cat]
        lines.append(f"| {cat} | {d['found']} / {d['total']} |")

    unmatched = res["unmatched_findings"]
    lines += ["", "## Findings non catalogués (à qualifier)", ""]
    if unmatched:
        lines += ["| Finding | Source | OWASP | Endpoint |", "|---|---|---|---|"]
        for f in unmatched:
            lines.append(f"| {f['title']} | {f['source']} | {f['owasp'] or '—'} "
                         f"| {f['endpoint'] or '—'} |")
    else:
        lines.append("_Aucun — tous les findings correspondent à la vérité terrain._")
    lines.append("")
    return "\n".join(lines)


def print_summary(res: dict) -> None:
    c, m = res["counts"], res["metrics"]
    print("=" * 60)
    print(f"ÉVALUATION — {res.get('benchmark', '')} / {res.get('target', '')}")
    print("=" * 60)
    print(f"  Rappel                 : {_fmt_pct(m['recall'])} "
          f"({c['true_positives']}/{c['ground_truth_items']} items trouvés)")
    print(f"  Précision (borne basse): {_fmt_pct(m['precision_lower_bound'])}")
    print(f"  F1 (borne basse)       : {_fmt_pct(m['f1_lower_bound'])}")
    print(f"  Faux négatifs          : {c['false_negatives']}")
    print(f"  Findings non catalogués: {c['unmatched_findings']}")
    missed = [pi["title"] for pi in res["per_item"] if not pi["found"]]
    if missed:
        print("  Manqués :")
        for t in missed:
            print(f"    - {t}")
    print("=" * 60)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Évaluation qualité d'une campagne PENTAGON.")
    p.add_argument("campaign", help="JSON de campagne (results/campaign_*.json)")
    p.add_argument("--ground-truth", default=_DEFAULT_GT,
                   help=f"JSON de vérité terrain (défaut : {_DEFAULT_GT})")
    p.add_argument("--out", default="benchmark",
                   help="Dossier de sortie des rapports (défaut : benchmark/)")
    p.add_argument("--no-report", action="store_true",
                   help="Afficher les métriques sans écrire de fichier")
    args = p.parse_args(argv)

    try:
        campaign = _load_json(args.campaign)
        ground_truth = _load_json(args.ground_truth)
    except (OSError, json.JSONDecodeError) as e:
        print(f"Erreur de lecture : {e}", file=sys.stderr)
        return 2

    res = score_campaign(campaign, ground_truth)
    print_summary(res)

    if not args.no_report:
        os.makedirs(args.out, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base = os.path.join(args.out, f"quality_report_{ts}")
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2)
        with open(base + ".md", "w", encoding="utf-8") as f:
            f.write(render_markdown(res))
        print(f"Rapport écrit : {base}.md  /  {base}.json")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
