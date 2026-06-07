"""
Outil de sondage d'API (API Prober) pour PENTAGON.

Cet outil teste une liste d'endpoints d'API et analyse les réponses
pour détecter des anomalies de contrôle d'accès et d'exposition de
données sensibles.

Conçu pour être GÉNÉRIQUE : prend en entrée des endpoints découverts
dynamiquement (par l'analyseur JS) et applique des règles d'analyse
universelles, sans connaissance spécifique d'une cible.

Utilisé par : Agent Web App (PTES phase 4 — Vulnerability Analysis)
Standards :
- OWASP WSTG-ATHZ (Authorization Testing)
- OWASP API Security Top 10 (API1: Broken Object Level Authorization)
- MITRE ATT&CK T1190 (Exploit Public-Facing Application)

Niveau de risque : ACTIF (envoie des requêtes vers la cible)
"""

import re
import requests
from datetime import datetime, timezone
from typing import Any


DEFAULT_TIMEOUT = 20
DEFAULT_HEADERS = {"User-Agent": "PENTAGON-WebApp-Agent/1.0"}

# Noms de champs considérés comme sensibles (génériques, multi-applications)
SENSITIVE_FIELD_NAMES = [
    "password", "passwd", "pwd", "hash",
    "creditcard", "credit_card", "card_number", "cardnumber", "cvv",
    "ssn", "social_security",
    "token", "secret", "api_key", "apikey", "private_key",
    "resettoken", "reset_token",
    "iban", "bank_account",
]


def run_api_probe(
    base_url: str,
    endpoints: list[str],
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Teste une liste d'endpoints d'API et analyse les réponses.
    
    Args:
        base_url: URL de base de l'API (ex: "https://backend.com/api")
                  Peut être vide si les endpoints sont déjà des URLs complètes.
        endpoints: liste de chemins ou d'URLs à tester (ex: ["/users", "/products"]).
        timeout: délai d'attente par requête.
    
    Returns:
        Dictionnaire structuré contenant :
        - status: "success" ou "error"
        - base_url: base testée
        - endpoints_tested: nombre d'endpoints testés
        - results: liste détaillée par endpoint
        - access_control_findings: endpoints accessibles sans auth (suspects)
        - data_exposure_findings: endpoints exposant des données sensibles
        - summary: statistiques agrégées
    """
    started_at = datetime.now(timezone.utc)
    
    result: dict[str, Any] = {
        "status": "success",
        "base_url": base_url,
        "endpoints_tested": 0,
        "results": [],
        "access_control_findings": [],
        "data_exposure_findings": [],
        "summary": {
            "accessible_without_auth": 0,
            "protected": 0,
            "errors": 0,
            "sensitive_data_exposed": 0,
        },
        "duration_seconds": None,
        "error": None,
    }
    
    try:
        for endpoint in endpoints:
            # Construit l'URL complète
            if endpoint.startswith("http"):
                url = endpoint
            else:
                # Joint base_url et endpoint proprement
                url = base_url.rstrip("/") + "/" + endpoint.lstrip("/")
            
            endpoint_result = _probe_single_endpoint(url, endpoint, timeout)
            result["results"].append(endpoint_result)
            result["endpoints_tested"] += 1
            
            # Agrégation des statistiques
            status_code = endpoint_result["status_code"]
            if status_code is None:
                result["summary"]["errors"] += 1
            elif status_code == 200:
                result["summary"]["accessible_without_auth"] += 1
                
                # Anomalie : 200 sans authentification sur un endpoint de données
                if endpoint_result["returns_json"]:
                    result["access_control_findings"].append({
                        "endpoint": endpoint,
                        "url": url,
                        "status_code": status_code,
                        "reason": "Endpoint JSON accessible sans authentification",
                        "owasp": "A01:2021 Broken Access Control",
                    })
                
                # Exposition de données sensibles
                if endpoint_result["sensitive_fields_found"]:
                    result["summary"]["sensitive_data_exposed"] += 1
                    result["data_exposure_findings"].append({
                        "endpoint": endpoint,
                        "url": url,
                        "sensitive_fields": endpoint_result["sensitive_fields_found"],
                        "reason": "Champs sensibles exposés dans la réponse",
                        "owasp": "A01:2021 / A02:2021",
                    })
            elif status_code in (401, 403):
                result["summary"]["protected"] += 1
            else:
                result["summary"]["errors"] += 1
    
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"
    
    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    
    return result


def _probe_single_endpoint(url: str, endpoint: str, timeout: int) -> dict[str, Any]:
    """
    Teste un endpoint unique en GET (sans authentification) et analyse la réponse.
    """
    endpoint_result = {
        "endpoint": endpoint,
        "url": url,
        "status_code": None,
        "content_type": None,
        "returns_json": False,
        "response_size": 0,
        "sensitive_fields_found": [],
        "record_count": None,
        "raw_json_data": None,
        "error": None,
    }
    
    try:
        response = requests.get(url, timeout=timeout, headers=DEFAULT_HEADERS)
        
        endpoint_result["status_code"] = response.status_code
        endpoint_result["content_type"] = response.headers.get("content-type", "")[:50]
        endpoint_result["response_size"] = len(response.content)
        
        # Détecte si c'est du JSON
        if "json" in endpoint_result["content_type"].lower():
            endpoint_result["returns_json"] = True
            
            try:
                data = response.json()
                
                # Compte les enregistrements si c'est une liste
                if isinstance(data, list):
                    endpoint_result["record_count"] = len(data)
                
                # Cherche des champs sensibles dans la réponse
                endpoint_result["sensitive_fields_found"] = _find_sensitive_fields(data)
                # Conserve les données brutes pour analyse approfondie (data_analyzer)
                # uniquement si des champs sensibles sont présents (économie de mémoire)
                if endpoint_result["sensitive_fields_found"]:
                    endpoint_result["raw_json_data"] = data
            except Exception:
                pass
    
    except requests.exceptions.Timeout:
        endpoint_result["error"] = "Timeout"
    except requests.exceptions.RequestException as e:
        endpoint_result["error"] = f"{type(e).__name__}"
    
    return endpoint_result


def _find_sensitive_fields(data: Any, found: set | None = None) -> list[str]:
    """
    Parcourt récursivement une structure JSON pour trouver des noms de
    champs sensibles (password, creditCard, token, etc.).
    
    Générique : détecte les patterns sensibles quelle que soit l'application.
    """
    if found is None:
        found = set()
    
    if isinstance(data, dict):
        for key, value in data.items():
            key_lower = key.lower().replace("_", "").replace("-", "")
            for sensitive in SENSITIVE_FIELD_NAMES:
                sensitive_normalized = sensitive.replace("_", "")
                if sensitive_normalized in key_lower:
                    found.add(key)
            # Récursion sur les valeurs
            _find_sensitive_fields(value, found)
    elif isinstance(data, list):
        # On n'analyse que le premier élément (structure représentative)
        if data:
            _find_sensitive_fields(data[0], found)
    
    return sorted(found)
