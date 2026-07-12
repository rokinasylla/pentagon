#!/usr/bin/env python3
"""
Génère un rapport PDF PENTAGON à partir d'un JSON de campagne existant.

Usage :
  python generate_report.py results/campaign_xxx.json
  python generate_report.py results/campaign_xxx.json --output rapport.pdf
  python generate_report.py results/campaign_xxx.json --operator rokhaya

Le JSON est produit par une campagne (pentagon.py) et sauvegardé dans results/.
Le PDF est écrit dans reports/ par défaut (ou au chemin --output).
"""

import argparse
import sys

from pentagon.agents.reporting_agent import ReportingAgent


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="generate_report",
        description="Rapport PDF PENTAGON depuis un JSON de campagne.")
    parser.add_argument("campaign_json", help="Chemin du JSON de campagne.")
    parser.add_argument("--output", "-o", help="Chemin du PDF de sortie.")
    parser.add_argument("--operator", default="",
                        help="Nom de l'opérateur (traçabilité).")
    args = parser.parse_args(argv)

    try:
        path = ReportingAgent().run(
            campaign=args.campaign_json,
            output_path=args.output,
            operator=args.operator,
        )
    except FileNotFoundError:
        print(f"❌ Fichier introuvable : {args.campaign_json}")
        return 2
    except RuntimeError as e:
        print(f"❌ {e}")
        return 1

    print(f"✓ Rapport disponible : {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
