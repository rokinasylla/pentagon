"""
Outil WHOIS pour PENTAGON.

Cet outil effectue une requête WHOIS sur un domaine et retourne
les informations publiques associées : registrar, dates de création
et d'expiration, serveurs DNS, contacts publics, etc.

Utilisé par : Agent OSINT (PTES phase 2 — Intelligence Gathering)
Standards : OWASP WSTG-INFO-08, MITRE ATT&CK T1590
"""

import whois
from datetime import datetime, timezone
from typing import Any
import logging
import warnings

# Silence les warnings et logs verbeux de python-whois et socket
logging.getLogger("whois").setLevel(logging.CRITICAL)
warnings.filterwarnings("ignore")

def run_whois(domain: str) -> dict[str, Any]:
    """
    Effectue une requête WHOIS sur un domaine.
    
    Args:
        domain: nom de domaine à interroger (ex: "techshop.onrender.com")
    
    Returns:
        Un dictionnaire structuré contenant :
        - status: "success" ou "error"
        - domain: le domaine interrogé
        - registrar: l'enregistreur du domaine
        - creation_date: date de création
        - expiration_date: date d'expiration
        - name_servers: liste des serveurs DNS
        - emails: emails de contact publics
        - org: organisation propriétaire
        - country: pays d'enregistrement
        - raw: réponse brute (utile pour debug)
        - error: message d'erreur le cas échéant
    """
    result: dict[str, Any] = {
        "status": "success",
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "emails": [],
        "org": None,
        "country": None,
        "raw": None,
        "error": None,
    }
    
    try:
        # Exécute la requête WHOIS
        w = whois.whois(domain)
        
        # Extrait les informations clés
        result["registrar"] = w.registrar
        result["org"] = w.org
        result["country"] = w.country
        
        # Les dates peuvent être des objets datetime ou des listes
        result["creation_date"] = _normalize_date(w.creation_date)
        result["expiration_date"] = _normalize_date(w.expiration_date)
        
        # Les serveurs DNS et emails peuvent être strings ou listes
        result["name_servers"] = _normalize_list(w.name_servers)
        result["emails"] = _normalize_list(w.emails)
        
        # Stocke la réponse brute pour audit/debug
        result["raw"] = str(w)
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"
    
    return result


def _normalize_date(date_value: Any) -> str | None:
    """
    Normalise une date WHOIS en chaîne ISO.
    
    Les WHOIS retournent parfois une date unique, parfois une liste
    de dates (cas des domaines avec plusieurs registrars historiques).
    """
    if date_value is None:
        return None
    
    if isinstance(date_value, list):
        date_value = date_value[0] if date_value else None
    
    if isinstance(date_value, datetime):
        return date_value.isoformat()
    
    return str(date_value) if date_value else None


def _normalize_list(value: Any) -> list[str]:
    """
    Normalise une valeur en liste de chaînes.
    
    Les WHOIS retournent parfois un string unique, parfois une liste.
    """
    if value is None:
        return []
    
    if isinstance(value, str):
        return [value]
    
    if isinstance(value, list):
        return [str(item) for item in value if item]
    
    return [str(value)]
