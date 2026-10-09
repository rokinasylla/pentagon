"""
Outil d'analyse des méthodes HTTP pour PENTAGON.

Détecte les méthodes HTTP dangereuses exposées par une cible — une faille de
CONFIGURATION du serveur, située EN DEHORS de l'OWASP Top 10 applicatif :

- **TRACE** activé → Cross-Site Tracing (XST) : permet de contourner la
  protection HttpOnly des cookies en faisant réfléchir les en-têtes par le
  serveur.
- **PUT / DELETE / PATCH / CONNECT** exposées → écriture, suppression ou
  tunneling potentiellement non autorisés.

GARDE-FOU « prouver, jamais ravager » : l'outil est **non destructif**. Il lit
l'en-tête `Allow` renvoyé par une requête OPTIONS et teste UNIQUEMENT TRACE
(qui ne fait que réfléchir la requête, sans rien modifier). Il n'émet
**JAMAIS** de PUT/DELETE/PATCH réel : ces méthodes sont seulement SIGNALÉES
lorsqu'elles sont annoncées par le serveur.

Conçu pour être GÉNÉRIQUE : applicable à toute cible web, sans configuration.

Utilisé par : Agent Web App (PTES phase 4).
Standards :
- OWASP WSTG-CONF-06 (Test HTTP Methods)
- CWE-650 (Trusting HTTP Permission Methods on the Server Side)
- MITRE ATT&CK T1190

Niveau de risque : ACTIF léger (1 requête OPTIONS + 1 requête TRACE).
Requiert la catégorie RoE 'active_scan'.
"""

import secrets
from datetime import datetime, timezone
from typing import Any

import requests


DEFAULT_TIMEOUT = 20
DEFAULT_HEADERS = {"User-Agent": "PENTAGON-WebApp-Agent/1.0"}

# Méthodes considérées dangereuses si exposées (hors GET/HEAD/POST/OPTIONS).
DANGEROUS_METHODS = {
    "PUT": ("Écriture de ressources potentiellement non autorisée", "high"),
    "DELETE": ("Suppression de ressources potentiellement non autorisée", "high"),
    "PATCH": ("Modification partielle potentiellement non autorisée", "medium"),
    "CONNECT": ("Tunneling (proxy) potentiellement abusable", "medium"),
    "TRACE": ("Cross-Site Tracing (XST) possible", "medium"),
    "TRACK": ("Variante de TRACE (XST) possible", "medium"),
}


def run_http_methods_scan(target_url: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """
    Analyse les méthodes HTTP exposées par une cible.

    Args:
        target_url: URL de la cible.
        timeout: délai d'attente réseau.

    Returns:
        Dict normalisé :
        {
          "status": "success" | "error",
          "target_url", "http_status",
          "allow_methods": [...],            # méthodes annoncées par OPTIONS
          "dangerous_methods_allowed": [...],# sous-ensemble dangereux annoncé
          "trace_enabled": bool,             # TRACE actif ET réfléchissant (XST)
          "findings": [{id, title, severity, evidence, standard}],
          "error": "..."                     # si status == error
        }
    """
    started_at = datetime.now(timezone.utc)
    if not target_url.startswith("http"):
        target_url = f"https://{target_url}"

    result: dict[str, Any] = {
        "status": "success",
        "target_url": target_url,
        "http_status": None,
        "allow_methods": [],
        "dangerous_methods_allowed": [],
        "trace_enabled": False,
        "findings": [],
        "duration_seconds": None,
        "error": None,
    }
    findings: list[dict[str, Any]] = []

    try:
        # 1) OPTIONS → en-tête Allow (méthodes annoncées par le serveur).
        resp = requests.options(target_url, timeout=timeout,
                                headers=DEFAULT_HEADERS, allow_redirects=True)
        result["http_status"] = resp.status_code
        allow = resp.headers.get("Allow") or resp.headers.get("allow") or ""
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        result["allow_methods"] = methods

        for m in methods:
            if m in DANGEROUS_METHODS and m not in ("TRACE", "TRACK"):
                desc, sev = DANGEROUS_METHODS[m]
                result["dangerous_methods_allowed"].append(m)
                findings.append(_f(f"http-method-{m.lower()}",
                                   f"Méthode HTTP dangereuse exposée : {m}",
                                   sev, f"OPTIONS annonce '{m}' dans Allow — {desc}",
                                   "WSTG-CONF-06 / CWE-650"))

        # 2) Test TRACE (non destructif : réfléchit seulement la requête).
        if _trace_reflects(target_url, timeout):
            result["trace_enabled"] = True
            if "TRACE" not in result["dangerous_methods_allowed"]:
                result["dangerous_methods_allowed"].append("TRACE")
            findings.append(_f("http-method-trace",
                               "Méthode TRACE active (Cross-Site Tracing)",
                               "medium",
                               "TRACE réfléchit la requête (marqueur retrouvé) → "
                               "contournement possible de HttpOnly",
                               "WSTG-CONF-06 / CWE-650"))

    except requests.exceptions.Timeout:
        result["status"] = "error"
        result["error"] = f"Timeout après {timeout}s"
    except requests.exceptions.RequestException as e:
        result["status"] = "error"
        result["error"] = f"Erreur réseau : {type(e).__name__}: {e}"

    result["findings"] = findings
    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    return result


def _f(fid: str, title: str, severity: str, evidence: str, standard: str) -> dict[str, Any]:
    """Construit un finding normalisé."""
    return {"id": fid, "title": title, "severity": severity,
            "evidence": evidence, "standard": standard}


def _trace_reflects(target_url: str, timeout: int) -> bool:
    """
    Teste si TRACE est actif ET réfléchit la requête (condition du XST).

    On envoie un en-tête marqueur unique ; si le corps de la réponse le renvoie,
    le serveur réfléchit la requête (TRACE exploitable). Non destructif.
    """
    marker = "pentagon-" + secrets.token_hex(6)
    try:
        resp = requests.request(
            "TRACE", target_url, timeout=timeout,
            headers={**DEFAULT_HEADERS, "X-Pentagon-Trace": marker},
            allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return False
    if resp.status_code != 200:
        return False
    body = resp.text or ""
    # XST : le marqueur (ou le mot-clé TRACE) est réfléchi dans le corps.
    return marker in body or "TRACE " in body.upper()[:200]


if __name__ == "__main__":
    import json
    import sys
    tgt = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(run_http_methods_scan(tgt), indent=2, ensure_ascii=False, default=str))
