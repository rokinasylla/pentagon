#!/usr/bin/env python3
"""
Tests PURS de l'outil d'évaluation (pentagon/tools/evaluation_tool.py).
Aucun réseau, aucun LLM — scoring déterministe sur des dicts synthétiques.
"""

from pentagon.tools.evaluation_tool import (
    normalize_owasp, normalize_cwe, collect_findings, _match_score,
    score_campaign,
)

results = []


def check(name, condition):
    results.append(bool(condition))
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


# Vérité terrain minimale : 3 items (SQLi login, XSS stocké, IDOR orders).
GT = {
    "benchmark": "TEST",
    "items": [
        {"id": "sqli", "title": "SQLi login", "owasp": "A03", "cwe": ["CWE-89"],
         "keywords": ["sql", "injection"], "endpoint": "/api/auth/login",
         "expected": "proven"},
        {"id": "xss", "title": "XSS stocké", "owasp": "A03", "cwe": ["CWE-79"],
         "keywords": ["xss", "stocké"], "endpoint": "/api/comments",
         "expected": "proven"},
        {"id": "idor", "title": "IDOR orders", "owasp": "A01",
         "cwe": ["CWE-639"], "keywords": ["idor", "orders"],
         "endpoint": "/api/orders", "expected": "detected"},
    ],
}


def _campaign(proven=None, detected=None):
    return {
        "target": "t", "campaign_id": "c",
        "exploitation_result": {"analysis": {"exploited_vulnerabilities": proven or []}},
        "web_app_result": {"analysis": {"vulnerabilities": detected or []}},
    }


def test_normalizers():
    print("test_normalizers")
    check("owasp 'A07:2021' -> A07", normalize_owasp("A07:2021 ...") == "A07")
    check("owasp 'a3' -> A03", normalize_owasp("a3") == "A03")
    check("owasp vide -> ''", normalize_owasp("") == "")
    check("cwe 'cwe-89' -> CWE-89", normalize_cwe("cwe-89") == "CWE-89")
    check("cwe 'CWE 79' -> CWE-79", normalize_cwe("CWE 79") == "CWE-79")


def test_collect_findings():
    print("test_collect_findings")
    camp = _campaign(
        proven=[{"title": "SQLi", "owasp_top10": "A03:2021", "cwe": "CWE-89",
                 "affected_endpoint": "/api/auth/login"}],
        detected=[{"title": "Fuite", "owasp": "A02", "cwe": "CWE-200",
                   "affected_endpoint": "/users"}],
    )
    f = collect_findings(camp)
    check("2 findings collectés", len(f) == 2)
    check("source proven présent", any(x["source"] == "proven" for x in f))
    check("source detected présent", any(x["source"] == "detected" for x in f))
    check("cwe normalisé en set", {"CWE-89"} == next(x["cwe"] for x in f if x["source"] == "proven"))


def test_match_score():
    print("test_match_score")
    item = GT["items"][0]  # sqli
    f_cwe = {"source": "proven", "title": "Faille X", "owasp": "A03",
             "cwe": {"CWE-89"}, "endpoint": "/api/auth/login"}
    f_kw = {"source": "proven", "title": "Injection SQL login", "owasp": "",
            "cwe": set(), "endpoint": ""}
    f_no = {"source": "detected", "title": "En-tête CSP manquant", "owasp": "A05",
            "cwe": {"CWE-693"}, "endpoint": "/"}
    check("match par CWE (+endpoint+owasp) > match par mot-clé seul",
          _match_score(f_cwe, item) > _match_score(f_kw, item))
    check("match par mot-clé > 0", _match_score(f_kw, item) > 0)
    check("aucun signal -> 0", _match_score(f_no, item) == 0.0)


def test_perfect_recall():
    print("test_perfect_recall")
    camp = _campaign(proven=[
        {"title": "SQLi bypass login", "owasp_top10": "A03", "cwe": "CWE-89",
         "affected_endpoint": "/api/auth/login"},
        {"title": "XSS stocké commentaires", "owasp_top10": "A03", "cwe": "CWE-79",
         "affected_endpoint": "/api/comments"},
        {"title": "IDOR orders", "owasp_top10": "A01", "cwe": "CWE-639",
         "affected_endpoint": "/api/orders"},
    ])
    r = score_campaign(camp, GT)
    check("rappel = 1.0", r["metrics"]["recall"] == 1.0)
    check("3 TP", r["counts"]["true_positives"] == 3)
    check("0 FN", r["counts"]["false_negatives"] == 0)
    check("0 non catalogué", r["counts"]["unmatched_findings"] == 0)
    check("précision borne basse = 1.0", r["metrics"]["precision_lower_bound"] == 1.0)


def test_partial_and_fp():
    print("test_partial_and_fp")
    # Trouve SQLi (prouvé) + un finding hors catalogue ; manque XSS et IDOR.
    camp = _campaign(proven=[
        {"title": "SQLi login", "owasp_top10": "A03", "cwe": "CWE-89",
         "affected_endpoint": "/api/auth/login"},
        {"title": "En-tête HSTS manquant", "owasp_top10": "A05", "cwe": "CWE-319",
         "affected_endpoint": "/"},
    ])
    r = score_campaign(camp, GT)
    check("1 TP", r["counts"]["true_positives"] == 1)
    check("2 FN", r["counts"]["false_negatives"] == 2)
    check("rappel ~ 1/3 (arrondi 4 déc.)", abs(r["metrics"]["recall"] - 1 / 3) < 1e-3)
    check("1 finding non catalogué", r["counts"]["unmatched_findings"] == 1)
    check("précision borne basse = 0.5", r["metrics"]["precision_lower_bound"] == 0.5)


def test_depth_detected_only():
    print("test_depth_detected_only")
    # SQLi attendu 'proven' mais seulement DÉTECTÉ -> trouvé mais depth_ok False.
    camp = _campaign(detected=[
        {"title": "Injection SQL possible", "owasp": "A03", "cwe": "CWE-89",
         "affected_endpoint": "/api/auth/login"},
    ])
    r = score_campaign(camp, GT)
    sqli = next(pi for pi in r["per_item"] if pi["id"] == "sqli")
    check("item trouvé", sqli["found"])
    check("profondeur NON OK (prouvé attendu, seulement détecté)", not sqli["depth_ok"])


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — evaluation_tool")
    print("=" * 70)
    for t in (test_normalizers, test_collect_findings, test_match_score,
              test_perfect_recall, test_partial_and_fp, test_depth_detected_only):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
