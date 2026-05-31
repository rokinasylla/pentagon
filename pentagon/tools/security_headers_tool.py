"""
Outil d'analyse des en-têtes de sécurité HTTP pour PENTAGON.

Cet outil examine les en-têtes HTTP et les cookies d'une cible pour
détecter les en-têtes de sécurité manquants ou mal configurés, ainsi
que les cookies sans attributs de protection.

Conçu pour être GÉNÉRIQUE : analyse universelle applicable à tout site web.

Utilisé par : Agent Web App (PTES phase 4 — Vulnerability Analysis)
Standards :
- OWASP WSTG-CONF (Configuration Management Testing)
- OWASP Secure Headers Project
- OWASP A05:2021 (Security Misconfiguration)
- MITRE ATT&CK T1190

Niveau de risque : ACTIF mais très léger (1 requête).
"""

import requests
from datetime import datetime, timezone
from typing import Any


DEFAULT_TIMEOUT = 20
DEFAULT_HEADERS = {"User-Agent": "PENTAGON-WebApp-Agent/1.0"}


# En-têtes de sécurité recommandés, avec leur niveau de criticité si absent
SECURITY_HEADERS = {
    "content-security-policy": {
        "severity": "high",
        "description": "Protège contre XSS et injection de contenu",
        "owasp": "A05:2021",
    },
    "strict-transport-security": {
        "severity": "high",
        "description": "Force HTTPS, protège contre les attaques downgrade",
        "owasp": "A05:2021",
    },
    "x-frame-options": {
        "severity": "medium",
        "description": "Protège contre le clickjacking",
        "owasp": "A05:2021",
    },
    "x-content-type-options": {
        "severity": "medium",
        "description": "Empêche le MIME-sniffing",
        "owasp": "A05:2021",
    },
    "referrer-policy": {
        "severity": "low",
        "description": "Contrôle les informations de referrer transmises",
        "owasp": "A05:2021",
    },
    "permissions-policy": {
        "severity": "low",
        "description": "Restreint l'accès aux API du navigateur",
        "owasp": "A05:2021",
    },
}

# En-têtes qui RÉVÈLENT des informations (leur présence est un problème)
INFO_DISCLOSURE_HEADERS = {
    "server": "Révèle le serveur web et parfois sa version",
    "x-powered-by": "Révèle la technologie backend (PHP, ASP.NET, etc.)",
    "x-aspnet-version": "Révèle la version exacte d'ASP.NET",
    "x-generator": "Révèle le CMS ou générateur utilisé",
}


def run_security_headers_scan(
    target_url: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Analyse les en-têtes de sécurité HTTP et les cookies d'une cible.
    
    Args:
        target_url: URL de la cible (ex: "https://exemple.com")
        timeout: délai d'attente.
    
    Returns:
        Dictionnaire structuré contenant :
        - status: "success" ou "error"
        - target_url: URL analysée
        - http_status: code HTTP de la réponse
        - missing_security_headers: en-têtes de sécurité absents
        - present_security_headers: en-têtes de sécurité présents
        - info_disclosure_headers: en-têtes qui révèlent des informations
        - cookie_issues: problèmes de configuration des cookies
        - all_headers: tous les en-têtes reçus (pour audit)
        - security_score: score sur 100
        - summary: statistiques
    """
    started_at = datetime.now(timezone.utc)
    
    if not target_url.startswith("http"):
        target_url = f"https://{target_url}"
    
    result: dict[str, Any] = {
        "status": "success",
        "target_url": target_url,
        "http_status": None,
        "missing_security_headers": [],
        "present_security_headers": [],
        "info_disclosure_headers": [],
        "cookie_issues": [],
        "all_headers": {},
        "security_score": 0,
        "summary": {
            "missing_count": 0,
            "info_leaks_count": 0,
            "cookie_issues_count": 0,
        },
        "duration_seconds": None,
        "error": None,
    }
    
    try:
        response = requests.get(
            target_url,
            timeout=timeout,
            headers=DEFAULT_HEADERS,
            allow_redirects=True,
        )
        
        result["http_status"] = response.status_code
        
        # Normalise les en-têtes en minuscules pour comparaison
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        result["all_headers"] = dict(response.headers)
        
        # 1. Vérifie les en-têtes de sécurité
        for header_name, info in SECURITY_HEADERS.items():
            if header_name in headers_lower:
                result["present_security_headers"].append({
                    "header": header_name,
                    "value": headers_lower[header_name][:100],
                })
            else:
                result["missing_security_headers"].append({
                    "header": header_name,
                    "severity": info["severity"],
                    "description": info["description"],
                    "owasp": info["owasp"],
                })
        
        # 2. Vérifie les en-têtes de divulgation d'information
        for header_name, description in INFO_DISCLOSURE_HEADERS.items():
            if header_name in headers_lower:
                result["info_disclosure_headers"].append({
                    "header": header_name,
                    "value": headers_lower[header_name][:100],
                    "description": description,
                })
        
        # 3. Analyse les cookies
        result["cookie_issues"] = _analyze_cookies(response)
        
        # 4. Calcule un score de sécurité
        result["security_score"] = _compute_security_score(result)
        
        # 5. Statistiques
        result["summary"] = {
            "missing_count": len(result["missing_security_headers"]),
            "info_leaks_count": len(result["info_disclosure_headers"]),
            "cookie_issues_count": len(result["cookie_issues"]),
        }
    
    except requests.exceptions.Timeout:
        result["status"] = "error"
        result["error"] = f"Timeout après {timeout}s"
    except requests.exceptions.RequestException as e:
        result["status"] = "error"
        result["error"] = f"Erreur réseau : {type(e).__name__}: {str(e)}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"
    
    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    
    return result


def _analyze_cookies(response: requests.Response) -> list[dict[str, Any]]:
    """
    Analyse les cookies de la réponse pour détecter les flags de sécurité manquants.
    """
    issues = []
    
    # Récupère les en-têtes Set-Cookie bruts
    set_cookie_headers = response.headers.get("set-cookie", "")
    if not set_cookie_headers:
        return issues
    
    # requests fusionne les Set-Cookie ; on analyse via response.cookies aussi
    for cookie in response.cookies:
        cookie_issues = []
        
        # Vérifie HttpOnly (protection contre vol via XSS)
        if not cookie.has_nonstandard_attr("HttpOnly") and not cookie.has_nonstandard_attr("httponly"):
            cookie_issues.append("HttpOnly manquant (vulnérable au vol via XSS)")
        
        # Vérifie Secure (transmission HTTPS uniquement)
        if not cookie.secure:
            cookie_issues.append("Secure manquant (transmissible en HTTP clair)")
        
        # Vérifie SameSite (protection CSRF)
        samesite = cookie.get_nonstandard_attr("SameSite") or cookie.get_nonstandard_attr("samesite")
        if not samesite:
            cookie_issues.append("SameSite manquant (vulnérable au CSRF)")
        
        if cookie_issues:
            issues.append({
                "cookie_name": cookie.name,
                "issues": cookie_issues,
            })
    
    return issues


def _compute_security_score(result: dict[str, Any]) -> int:
    """
    Calcule un score de sécurité sur 100 basé sur les findings.
    
    Score = 100 - pénalités pour headers manquants, fuites d'info, cookies.
    """
    score = 100
    
    # Pénalités par sévérité des headers manquants
    severity_penalty = {"high": 20, "medium": 10, "low": 5}
    for missing in result["missing_security_headers"]:
        score -= severity_penalty.get(missing["severity"], 5)
    
    # Pénalité pour divulgation d'information
    score -= len(result["info_disclosure_headers"]) * 5
    
    # Pénalité pour problèmes de cookies
    for cookie_issue in result["cookie_issues"]:
        score -= len(cookie_issue["issues"]) * 5
    
    return max(0, score)  # plancher à 0
