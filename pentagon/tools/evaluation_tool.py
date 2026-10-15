"""
Outil d'évaluation (Lot 6 — Qualité & métriques).

Compare les findings d'une campagne PENTAGON à une VÉRITÉ TERRAIN (catalogue
des vulnérabilités semées, ex. benchmark/vulnshop_ground_truth.json) et calcule
des métriques standard : PRÉCISION, RAPPEL, F1, avec les listes de vrais
positifs (TP), faux négatifs (FN) et findings non catalogués (FP candidats).

Fonction 100% PURE et hors-ligne : aucune requête réseau, aucun LLM. Elle opère
sur des dictionnaires déjà chargés (le JSON de campagne et le JSON de vérité
terrain), ce qui la rend testable facilement et de façon déterministe.

Méthodologie de rapprochement (documentée pour la rigueur académique) :
- Chaque finding est assigné à AU PLUS UN item de la vérité terrain, celui qui
  obtient le meilleur score de correspondance.
- Le score combine des signaux STABLES — le CWE (fort) et les mots-clés du
  titre (moyen) — l'OWASP et l'endpoint ne servant que de corroboration.
- Un item est un vrai positif (TP) si au moins un finding lui est assigné ; sinon
  c'est un faux négatif (FN). Un finding assigné à aucun item est un « FP
  candidat » (non catalogué) : la précision rapportée est donc une BORNE BASSE
  (hypothèse pessimiste : tout finding hors catalogue est compté comme faux
  positif), certains pouvant être de vraies failles hors périmètre.
"""

import re
from typing import Any

# Pondération des signaux de correspondance (voir méthodologie ci-dessus).
_W_CWE = 2.0      # CWE partagé = signal fort
_W_KEYWORD = 1.0  # mot-clé du titre = signal moyen
_W_ENDPOINT = 1.0 # endpoint corroborant
_W_OWASP = 0.5    # catégorie OWASP corroborante

_OWASP_RE = re.compile(r"\bA(\d{1,2})\b", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE[-\s]?(\d+)", re.IGNORECASE)


def normalize_owasp(value: str) -> str:
    """'A07:2021 ...' / 'a3' -> 'A03' ; chaîne vide si absent."""
    if not value:
        return ""
    m = _OWASP_RE.search(str(value))
    return f"A{int(m.group(1)):02d}" if m else ""


def normalize_cwe(value: str) -> str:
    """'cwe-89' / 'CWE 89' -> 'CWE-89' ; chaîne vide si absent."""
    if not value:
        return ""
    m = _CWE_RE.search(str(value))
    return f"CWE-{int(m.group(1))}" if m else ""


def _cwe_set(value) -> set[str]:
    """Normalise un CWE (str) ou une liste de CWE en ensemble {'CWE-89', ...}."""
    if isinstance(value, (list, tuple)):
        out = {normalize_cwe(v) for v in value}
    else:
        out = {normalize_cwe(value)}
    return {c for c in out if c}


def collect_findings(campaign: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extrait et normalise les findings d'une campagne (prouvés + détectés).

    source = 'proven' (agent Exploitation) ou 'detected' (agent Web App).
    """
    out: list[dict[str, Any]] = []

    exp = (campaign.get("exploitation_result") or {}).get("analysis", {}) or {}
    for v in exp.get("exploited_vulnerabilities", []) or []:
        out.append(_normalize_finding(v, "proven"))

    web = (campaign.get("web_app_result") or {}).get("analysis", {}) or {}
    for v in web.get("vulnerabilities", []) or []:
        out.append(_normalize_finding(v, "detected"))

    return out


def _normalize_finding(v: dict[str, Any], source: str) -> dict[str, Any]:
    return {
        "source": source,
        "title": str(v.get("title", "") or ""),
        "owasp": normalize_owasp(v.get("owasp_top10") or v.get("owasp") or ""),
        "cwe": _cwe_set(v.get("cwe")),
        "endpoint": str(v.get("affected_endpoint", "") or ""),
    }


def _match_score(finding: dict[str, Any], item: dict[str, Any]) -> float:
    """Score de correspondance finding<->item (0 = aucune correspondance)."""
    score = 0.0
    item_cwe = _cwe_set(item.get("cwe"))
    if finding["cwe"] and item_cwe and (finding["cwe"] & item_cwe):
        score += _W_CWE

    title = finding["title"].lower()
    if any(kw.lower() in title for kw in item.get("keywords", []) if kw):
        score += _W_KEYWORD

    # Les signaux forts (CWE/mot-clé) sont requis : sans eux, pas de match.
    if score == 0.0:
        return 0.0

    ep = (item.get("endpoint") or "").lower()
    if ep and (ep in finding["endpoint"].lower() or ep in title):
        score += _W_ENDPOINT
    if item.get("owasp") and finding["owasp"] == normalize_owasp(item["owasp"]):
        score += _W_OWASP
    return score


def _depth_ok(expected: str, sources: set[str]) -> bool:
    """Un item 'proven' exige une preuve ; 'detected' accepte détecté OU prouvé."""
    if expected == "proven":
        return "proven" in sources
    return bool(sources)  # 'detected' : toute présence suffit


def score_campaign(campaign: dict[str, Any],
                   ground_truth: dict[str, Any]) -> dict[str, Any]:
    """
    Évalue une campagne contre une vérité terrain.

    Returns un dict de métriques : precision, recall, f1 (+ bornes),
    compteurs TP/FN/FP, détail par item, findings non catalogués, et
    rappel par catégorie OWASP.
    """
    items = ground_truth.get("items", []) or []
    findings = collect_findings(campaign)

    # Assignation gloutonne : chaque finding -> son meilleur item (score max > 0).
    assigned_item_sources: dict[str, set[str]] = {it["id"]: set() for it in items}
    unmatched_findings: list[dict[str, Any]] = []

    for f in findings:
        best_id, best_score = None, 0.0
        for it in items:
            s = _match_score(f, it)
            if s > best_score:
                best_id, best_score = it["id"], s
        if best_id is not None:
            assigned_item_sources[best_id].add(f["source"])
        else:
            unmatched_findings.append({"title": f["title"], "source": f["source"],
                                       "owasp": f["owasp"], "endpoint": f["endpoint"]})

    # TP / FN par item + profondeur (prouvé vs détecté attendu).
    per_item: list[dict[str, Any]] = []
    tp = 0
    for it in items:
        srcs = assigned_item_sources[it["id"]]
        found = bool(srcs)
        depth_ok = _depth_ok(it.get("expected", "detected"), srcs)
        if found:
            tp += 1
        per_item.append({
            "id": it["id"], "title": it.get("title", ""),
            "owasp": normalize_owasp(it.get("owasp", "")),
            "expected": it.get("expected", "detected"),
            "found": found, "sources": sorted(srcs), "depth_ok": depth_ok,
        })

    total_items = len(items)
    fn = total_items - tp
    total_findings = len(findings)
    matched_findings = total_findings - len(unmatched_findings)
    fp = len(unmatched_findings)

    recall = tp / total_items if total_items else 0.0
    # Précision BORNE BASSE : tout finding non catalogué compté comme FP.
    precision_low = matched_findings / total_findings if total_findings else 0.0
    f1_low = (2 * precision_low * recall / (precision_low + recall)
              if (precision_low + recall) else 0.0)

    # Rappel par catégorie OWASP.
    by_owasp: dict[str, dict[str, int]] = {}
    for pi in per_item:
        cat = pi["owasp"] or "—"
        d = by_owasp.setdefault(cat, {"found": 0, "total": 0})
        d["total"] += 1
        if pi["found"]:
            d["found"] += 1

    return {
        "benchmark": ground_truth.get("benchmark", ""),
        "target": campaign.get("target", ""),
        "campaign_id": campaign.get("campaign_id", ""),
        "counts": {
            "ground_truth_items": total_items,
            "findings_total": total_findings,
            "true_positives": tp,
            "false_negatives": fn,
            "unmatched_findings": fp,
            "matched_findings": matched_findings,
        },
        "metrics": {
            "recall": round(recall, 4),
            "precision_lower_bound": round(precision_low, 4),
            "f1_lower_bound": round(f1_low, 4),
        },
        "per_item": per_item,
        "unmatched_findings": unmatched_findings,
        "recall_by_owasp": by_owasp,
    }
