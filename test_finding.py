#!/usr/bin/env python3
"""
Tests PURS du modèle Finding (pentagon/core/finding.py).

Aucun réseau : on valide le cycle de vie de preuve (détecté → prouvé →
confirmé), la monotonie des transitions, l'historique d'évidence, la
sérialisation, et la dérivation depuis un résultat de testeur.
"""

from pentagon.core.finding import (
    Finding, DETECTED, PROVEN, CONFIRMED, proof_rank, roe_action_for,
    make_finding, findings_from_result,
)

results = []


def check(name, condition):
    results.append(bool(condition))
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def test_defaults_and_ids():
    print("test_defaults_and_ids")
    f = Finding(session_id="s1", title="SSTI", category="ssti")
    check("id généré non vide", bool(f.id))
    check("created_at renseigné", bool(f.created_at))
    check("updated_at renseigné", bool(f.updated_at))
    check("état initial détecté", f.proof_state == DETECTED)
    check("état inconnu retombe sur détecté",
          Finding(session_id="s", title="t", category="c",
                  proof_state="bogus").proof_state == DETECTED)
    g = Finding(session_id="s1", title="autre", category="xss")
    check("deux findings = deux ids distincts", f.id != g.id)


def test_proof_rank():
    print("test_proof_rank")
    check("ordre détecté < prouvé < confirmé",
          proof_rank(DETECTED) < proof_rank(PROVEN) < proof_rank(CONFIRMED))
    check("état inconnu -> rang -1", proof_rank("??") == -1)


def test_promote_monotone():
    print("test_promote_monotone")
    f = Finding(session_id="s1", title="t", category="lfi")
    check("détecté -> prouvé avance", f.promote(PROVEN) is True)
    check("état = prouvé", f.proof_state == PROVEN)
    check("prouvé -> détecté NE régresse pas", f.promote(DETECTED) is False)
    check("toujours prouvé", f.proof_state == PROVEN)
    check("prouvé -> prouvé (égal) n'avance pas", f.promote(PROVEN) is False)
    check("prouvé -> confirmé avance", f.promote(CONFIRMED) is True)
    check("état = confirmé", f.proof_state == CONFIRMED)
    check("état inconnu refusé", f.promote("bogus") is False)


def test_evidence_history():
    print("test_evidence_history")
    f = Finding(session_id="s1", title="t", category="ssrf")
    before = f.updated_at
    entry = f.add_evidence("prove", "ssrf_tester", "canari joint + timeout",
                           at="2026-01-01T00:00:00+00:00")
    check("une entrée d'évidence", len(f.evidence) == 1)
    check("stage conservé", entry["stage"] == "prove")
    check("outil conservé", entry["tool"] == "ssrf_tester")
    check("horodatage conservé", entry["at"] == "2026-01-01T00:00:00+00:00")
    check("updated_at suit l'évidence", f.updated_at == "2026-01-01T00:00:00+00:00")
    check("updated_at a changé", f.updated_at != before)


def test_serialization_roundtrip():
    print("test_serialization_roundtrip")
    f = Finding(session_id="s1", title="SSTI", category="ssti",
                severity="critical", owasp="A03:2021", cwe="CWE-1336",
                affected_endpoint="https://v.me/api/render", confidence=0.97,
                proof_state=PROVEN)
    f.add_evidence("prove", "ssti_tester", "7331*7=51317")
    d = f.to_dict()
    check("to_dict contient l'état", d["proof_state"] == PROVEN)
    check("to_dict contient l'évidence", len(d["evidence"]) == 1)
    g = Finding.from_dict(d)
    check("roundtrip conserve l'id", g.id == f.id)
    check("roundtrip conserve l'endpoint",
          g.affected_endpoint == "https://v.me/api/render")
    check("roundtrip conserve l'évidence", g.evidence == f.evidence)
    check("from_dict ignore les champs inconnus",
          Finding.from_dict({**d, "zzz": 1}).id == f.id)


def test_roe_action_mapping():
    print("test_roe_action_mapping")
    check("ssti -> exploitation", roe_action_for("ssti") == "exploitation")
    check("csrf -> exploitation", roe_action_for("csrf") == "exploitation")
    check("catégorie inconnue -> exploitation (jamais passive)",
          roe_action_for("inconnue") == "exploitation")


def test_make_finding():
    print("test_make_finding")
    raw = {
        "title": "SSTI confirmée", "severity": "critical",
        "owasp": "A03:2021", "cwe": "CWE-1336",
        "affected_endpoint": "https://v.me/api/render", "param": "name",
        "payload": "{{7331*7}}", "evidence": "7331*7=51317", "confidence": 0.97,
    }
    f = make_finding("s1", "ssti", raw, tool="ssti_tester")
    check("titre repris", f.title == "SSTI confirmée")
    check("sévérité reprise", f.severity == "critical")
    check("endpoint repris", f.affected_endpoint == "https://v.me/api/render")
    check("param repris", f.param == "name")
    check("confiance reprise", abs(f.confidence - 0.97) < 1e-9)
    check("état par défaut = prouvé", f.proof_state == PROVEN)
    check("évidence brute devient 1re entrée (stage prove)",
          len(f.evidence) == 1 and f.evidence[0]["stage"] == "prove")
    # proof_state=detected -> stage detect, titre par défaut = catégorie
    g = make_finding("s1", "ssrf", {"severity": "high"},
                     proof_state=DETECTED)
    check("sans titre -> catégorie", g.title == "ssrf")
    check("état détecté respecté", g.proof_state == DETECTED)
    check("sans évidence brute -> pas d'entrée", len(g.evidence) == 0)


def test_findings_from_result():
    print("test_findings_from_result")
    result = {"findings": [
        {"title": "LFI", "severity": "high", "affected_endpoint": "u/1",
         "evidence": "root:x:0:0"},
        {"title": "LFI 2", "severity": "high", "affected_endpoint": "u/2"},
        "pas un dict",  # ignoré
    ]}
    fs = findings_from_result("s1", "lfi", result, tool="lfi_tester")
    check("deux findings dérivés (le non-dict ignoré)", len(fs) == 2)
    check("tous session s1", all(f.session_id == "s1" for f in fs))
    check("tous catégorie lfi", all(f.category == "lfi" for f in fs))
    check("tous prouvés", all(f.proof_state == PROVEN for f in fs))
    check("résultat None -> liste vide", findings_from_result("s", "lfi", None) == [])
    check("résultat sans findings -> liste vide",
          findings_from_result("s", "lfi", {"vulnerable": False}) == [])


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — core/finding")
    print("=" * 70)
    for t in (test_defaults_and_ids, test_proof_rank, test_promote_monotone,
              test_evidence_history, test_serialization_roundtrip,
              test_roe_action_mapping, test_make_finding,
              test_findings_from_result):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
