#!/usr/bin/env python3
"""
Tests PURS du magasin de Findings (pentagon/core/finding_store.py) et de
l'inférence de catégorie (pentagon/core/finding.py).

Aucun réseau, aucun LLM : on valide la dérivation depuis le résumé de campagne,
l'inférence de catégorie (CWE puis titre), la persistance disque (dossier
temporaire), la recherche par index/id et le remplacement.
"""

import os
import tempfile

from pentagon.core.finding import infer_category, DETECTED, PROVEN, CONFIRMED
from pentagon.core.finding_store import (
    finding_from_unified, findings_from_summary, save_findings, load_findings,
    get_or_init_findings, find_by_index, find_by_id, replace_finding,
)

results = []


def check(name, condition):
    results.append(bool(condition))
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def test_infer_category_by_cwe():
    print("test_infer_category_by_cwe")
    check("CWE-1336 -> ssti", infer_category(cwe="CWE-1336") == "ssti")
    check("CWE-918 -> ssrf", infer_category(cwe="CWE-918") == "ssrf")
    check("CWE-352 -> csrf", infer_category(cwe="CWE-352") == "csrf")
    check("CWE-22 -> lfi", infer_category(cwe="CWE-22") == "lfi")
    check("CWE-601 -> open_redirect", infer_category(cwe="CWE-601") == "open_redirect")
    check("CWE-89 -> sqli", infer_category(cwe="CWE-89") == "sqli")
    check("CWE-79 -> xss", infer_category(cwe="CWE-79") == "xss")


def test_infer_category_by_title():
    print("test_infer_category_by_title")
    check("titre SSTI", infer_category(title="Injection de template côté serveur") == "ssti")
    check("titre SSRF", infer_category(title="SSRF sur /api/fetch") == "ssrf")
    check("titre traversée -> lfi",
          infer_category(title="Traversée de répertoire") == "lfi")
    check("titre redirection ouverte",
          infer_category(title="Redirection ouverte vers domaine externe") == "open_redirect")
    check("titre JWT", infer_category(title="Token JWT forgeable") == "jwt")
    check("titre IDOR", infer_category(title="Accès horizontal (IDOR)") == "idor")
    check("inconnu -> vide", infer_category(title="Bannière verbeuse") == "")
    check("CWE prioritaire sur titre",
          infer_category(title="quelque chose XSS", cwe="CWE-918") == "ssrf")


def test_finding_from_unified():
    print("test_finding_from_unified")
    prouve = {"title": "SSTI", "severity": "critical", "source": "prouvée",
              "cwe": "CWE-1336", "endpoint": "https://v.me/api/render",
              "description": "7331*7=51317", "confidence": 0.97}
    f = finding_from_unified("s1", prouve, order=0)
    check("id stable session-rang", f.id == "s1-0")
    check("catégorie inférée", f.category == "ssti")
    check("source prouvée -> proven", f.proof_state == PROVEN)
    check("endpoint repris", f.affected_endpoint == "https://v.me/api/render")
    check("description -> évidence stage prove",
          f.evidence and f.evidence[0]["stage"] == "prove")

    detecte = {"title": "En-tête manquant", "severity": "low",
               "source": "détectée", "cwe": ""}
    g = finding_from_unified("s1", detecte, order=1)
    check("source détectée -> detected", g.proof_state == DETECTED)
    check("catégorie inconnue -> vide", g.category == "")


def test_findings_from_summary():
    print("test_findings_from_summary")
    summary = {"findings": [
        {"title": "SSTI", "source": "prouvée", "cwe": "CWE-1336",
         "endpoint": "u/render"},
        {"title": "CSRF", "source": "prouvée", "cwe": "CWE-352",
         "endpoint": "u/news"},
        "pas un dict",
    ]}
    fs = findings_from_summary("s1", summary)
    check("deux findings (non-dict ignoré)", len(fs) == 2)
    check("ids distincts et stables", [f.id for f in fs] == ["s1-0", "s1-1"])
    check("résumé None -> vide", findings_from_summary("s1", None) == [])
    check("résumé sans findings -> vide",
          findings_from_summary("s1", {"target": "x"}) == [])


def test_persistence_roundtrip():
    print("test_persistence_roundtrip")
    with tempfile.TemporaryDirectory() as d:
        summary = {"findings": [
            {"title": "SSTI", "source": "prouvée", "cwe": "CWE-1336",
             "endpoint": "u/render"}]}
        fs = findings_from_summary("sess-A", summary)
        path = save_findings(d, "sess-A", fs)
        check("fichier écrit", os.path.exists(path))
        reloaded = load_findings(d, "sess-A")
        check("rechargé: 1 finding", len(reloaded) == 1)
        check("rechargé: même id", reloaded[0].id == "sess-A-0")
        check("rechargé: même catégorie", reloaded[0].category == "ssti")
        check("session absente -> liste vide", load_findings(d, "zzz") == [])


def test_get_or_init_preserves_state():
    print("test_get_or_init_preserves_state")
    with tempfile.TemporaryDirectory() as d:
        summary = {"findings": [
            {"title": "SSTI", "source": "prouvée", "cwe": "CWE-1336",
             "endpoint": "u/render"}]}
        # 1er appel : dérive + persiste à l'état prouvé
        first = get_or_init_findings(d, "sess-B", summary)
        check("init -> proven", first[0].proof_state == PROVEN)
        # on confirme la faille et on persiste
        first[0].promote(CONFIRMED)
        save_findings(d, "sess-B", first)
        # 2e appel : l'état confirmé est CONSERVÉ (pas ré-initialisé à proven)
        again = get_or_init_findings(d, "sess-B", summary)
        check("état confirmé conservé", again[0].proof_state == CONFIRMED)


def test_lookup_and_replace():
    print("test_lookup_and_replace")
    summary = {"findings": [
        {"title": "A", "source": "prouvée", "cwe": "CWE-1336", "endpoint": "u/a"},
        {"title": "B", "source": "prouvée", "cwe": "CWE-352", "endpoint": "u/b"}]}
    fs = findings_from_summary("s1", summary)
    check("index 1 -> 1er", find_by_index(fs, 1).title == "A")
    check("index 2 -> 2e", find_by_index(fs, 2).title == "B")
    check("index 0 -> None", find_by_index(fs, 0) is None)
    check("index hors borne -> None", find_by_index(fs, 3) is None)
    check("index None -> None", find_by_index(fs, None) is None)
    check("find_by_id", find_by_id(fs, "s1-1").title == "B")
    check("find_by_id absent -> None", find_by_id(fs, "zz") is None)

    fs[0].promote(CONFIRMED)
    out = replace_finding(fs, fs[0])
    check("remplacement conserve la taille", len(out) == 2)
    check("remplacement par id", find_by_id(out, "s1-0").proof_state == CONFIRMED)


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — core/finding_store + infer_category")
    print("=" * 70)
    for t in (test_infer_category_by_cwe, test_infer_category_by_title,
              test_finding_from_unified, test_findings_from_summary,
              test_persistence_roundtrip, test_get_or_init_preserves_state,
              test_lookup_and_replace):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
