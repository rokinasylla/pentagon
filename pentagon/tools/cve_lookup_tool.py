"""
Outil de corrélation CVE pour PENTAGON.

Associe les COMPOSANTS détectés (serveur web, langage, service réseau avec leur
version) aux VULNÉRABILITÉS PUBLIQUES CONNUES (CVE), via l'API officielle du NVD
(National Vulnerability Database, NIST). Couvre l'OWASP A06:2021 (Composants
vulnérables et obsolètes) — souvent négligé car il faut croiser versions ↔ CVE.

Flux :
1. Extraction des couples (produit, version) depuis WhatWeb + Nmap.
2. Pour chaque composant versionné, interrogation du NVD (keywordSearch).
3. Normalisation : CVE id + score CVSS + sévérité → findings.

NB réseau : les requêtes vont vers l'API PUBLIQUE du NVD, PAS vers la cible
(aucun trafic offensif). Sans clé API, le NVD limite à ~5 requêtes / 30 s : on
plafonne le nombre de composants et on espace les appels.

L'import de `requests` est DIFFÉRÉ → les fonctions d'extraction et de parsing
(pures) sont testables hors-ligne.

Utilisé par : Agent Scanning.
Standards : OWASP A06:2021, CWE-1035/937, CVSS, MITRE T1595.
"""

import re
import time
from typing import Any


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")

# Noms de composants trop génériques pour une recherche CVE utile.
SKIP_PRODUCTS = {"http", "https", "html5", "title", "ip", "country", "cookies",
                 "script", "uncommonheaders", "metagenerator", "email", ""}


def _cvss_severity(score: float) -> str:
    """Mappe un score CVSS (0-10) vers une sévérité PENTAGON."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def extract_products(whatweb_data: dict[str, Any] | None,
                     nmap_data: dict[str, Any] | None) -> list[tuple[str, str]]:
    """
    Extrait les couples (produit, version) uniques depuis WhatWeb et Nmap.

    Ne garde que les composants AVEC une version (sinon pas de corrélation CVE
    fiable) et écarte les noms trop génériques.
    """
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: str):
        name = (name or "").strip()
        version = (version or "").strip()
        if not name or not version or name.lower() in SKIP_PRODUCTS:
            return
        key = (name.lower(), version)
        if key not in seen:
            seen.add(key)
            found.append((name, version))

    # Nmap : product + version propres.
    if isinstance(nmap_data, dict):
        for host_data in (nmap_data.get("hosts") or {}).values():
            for p in (host_data or {}).get("ports", []):
                if p.get("state") == "open" and p.get("product") and p.get("version"):
                    add(p["product"], p["version"])

    # WhatWeb : technologies -> cherche une version dans les 'values'.
    if isinstance(whatweb_data, dict):
        for tech in whatweb_data.get("technologies", []) or []:
            name = tech.get("name", "")
            for val in tech.get("values", []) or []:
                m = VERSION_RE.search(str(val))
                if m:
                    add(name, m.group(0))
                    break

    return found


def _parse_nvd_response(data: dict[str, Any], product: str,
                        version: str, max_cves: int = 5) -> dict[str, Any] | None:
    """
    Transforme une réponse NVD en un finding normalisé pour un composant.

    Returns:
        Un finding {id, title, severity, evidence, standard, cves[...]} si des
        CVE existent, sinon None.
    """
    vulns = (data or {}).get("vulnerabilities", []) or []
    cves: list[dict[str, Any]] = []

    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        score, severity = _extract_cvss(cve.get("metrics", {}))
        cves.append({"id": cve_id, "cvss": score, "severity": severity})

    if not cves:
        return None

    # Tri par score décroissant, on garde les plus graves.
    cves.sort(key=lambda c: c["cvss"] or 0, reverse=True)
    cves = cves[:max_cves]
    top = cves[0]
    max_score = top["cvss"] or 0.0

    ids = ", ".join(c["id"] for c in cves)
    return {
        "id": f"cve-{product.lower()}-{version}".replace(" ", "-"),
        "title": f"Composant à CVE connues : {product} {version}",
        "severity": _cvss_severity(max_score),
        "evidence": f"{len(cves)} CVE (max CVSS {max_score}) : {ids}",
        "standard": "OWASP A06:2021 / CVSS",
        "cves": cves,
        "component": f"{product} {version}",
    }


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float, str]:
    """Extrait (baseScore, baseSeverity) du meilleur bloc CVSS disponible."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        blocks = metrics.get(key) or []
        if blocks:
            data = blocks[0].get("cvssData", {})
            score = data.get("baseScore", 0.0) or 0.0
            sev = data.get("baseSeverity") or blocks[0].get("baseSeverity") or ""
            return float(score), str(sev)
    return 0.0, ""


def _query_nvd(product: str, version: str, timeout: float = 20.0) -> dict[str, Any] | None:
    """Interroge l'API NVD pour un composant (import requests différé)."""
    import requests
    try:
        resp = requests.get(
            NVD_API,
            params={"keywordSearch": f"{product} {version}", "resultsPerPage": 10},
            headers={"User-Agent": "PENTAGON-Scanning-Agent/1.0"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def run_cve_analysis(whatweb_data: dict[str, Any] | None = None,
                     nmap_data: dict[str, Any] | None = None,
                     max_products: int = 5,
                     delay: float = 6.0) -> dict[str, Any]:
    """
    Corrèle les composants détectés aux CVE connues (NVD).

    Returns:
        {
          "status": "success" | "error",
          "components_checked": [{product, version}],
          "findings": [{id, title, severity, evidence, standard, cves}],
          "note": "...",
          "error": "..."
        }
    """
    result: dict[str, Any] = {
        "status": "success",
        "components_checked": [],
        "findings": [],
        "note": None,
        "error": None,
    }

    components = extract_products(whatweb_data, nmap_data)
    if not components:
        result["note"] = "Aucun composant versionné détecté (rien à corréler)."
        return result

    components = components[:max_products]
    findings: list[dict[str, Any]] = []

    for i, (product, version) in enumerate(components):
        result["components_checked"].append({"product": product, "version": version})
        data = _query_nvd(product, version)
        if data is not None:
            finding = _parse_nvd_response(data, product, version)
            if finding:
                findings.append(finding)
        # Respecte la limite de débit du NVD entre deux appels.
        if i < len(components) - 1:
            time.sleep(delay)

    result["findings"] = findings
    if not findings:
        result["note"] = "Aucune CVE trouvée pour les composants détectés."
    return result


if __name__ == "__main__":
    import json
    import sys
    # Démo : extraction depuis un JSON de scan, ou recherche directe produit/version.
    if len(sys.argv) >= 3:
        print(json.dumps(run_cve_analysis(
            whatweb_data={"technologies": [{"name": sys.argv[1],
                                            "values": [sys.argv[2]]}]}),
            indent=2, ensure_ascii=False, default=str))
    else:
        print("Usage: python -m pentagon.tools.cve_lookup_tool <produit> <version>")
