"""
Outil Certificate Transparency (crt.sh) pour PENTAGON.

Cet outil interroge l'API publique crt.sh pour récupérer tous les certificats
SSL émis pour un domaine donné. Permet de découvrir des sous-domaines
oubliés ou non publiés, en restant 100% passif.

Utilisé par : Agent OSINT (PTES phase 2 — Intelligence Gathering)
Standards : 
- MITRE ATT&CK T1596.003 (Search Open Technical Databases: Digital Certificates)
- RFC 6962 (Certificate Transparency)
- OWASP WSTG-INFO-01

Niveau de risque : PASSIF (aucune interaction avec la cible)
"""

import requests
from datetime import datetime
from typing import Any


CRT_SH_API_URL = "https://crt.sh/"
DEFAULT_TIMEOUT = 30


def run_crtsh_lookup(
    domain: str,
    include_expired: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Interroge crt.sh pour découvrir les certificats SSL d'un domaine.
    
    Args:
        domain: domaine à interroger (ex: "rokina-sylla.me")
                Note : crt.sh recherche aussi les sous-domaines automatiquement.
        include_expired: inclure les certificats expirés (par défaut True,
                         car ils révèlent des sous-domaines historiques utiles).
        timeout: délai d'attente max en secondes.
    
    Returns:
        Dictionnaire structuré contenant :
        - status: "success" ou "error"
        - domain: le domaine interrogé
        - total_certificates: nombre total de certificats trouvés
        - unique_subdomains: liste dédupliquée des sous-domaines découverts
        - certificate_authorities: liste des CA utilisées
        - first_certificate_date: date du plus ancien certificat
        - latest_certificate_date: date du plus récent certificat
        - certificates: liste détaillée des certificats (limitée à 50)
        - summary: dict avec statistiques
        - error: message d'erreur le cas échéant
    """
    started_at = datetime.now()
    
    result: dict[str, Any] = {
        "status": "success",
        "domain": domain,
        "total_certificates": 0,
        "unique_subdomains": [],
        "certificate_authorities": [],
        "first_certificate_date": None,
        "latest_certificate_date": None,
        "certificates": [],
        "summary": {
            "subdomains_count": 0,
            "ca_count": 0,
            "wildcard_certificates": 0,
        },
        "error": None,
        "lookup_duration_seconds": None,
    }
    
    try:
        # Recherche tous les certificats contenant ce domaine
        # Le % est un wildcard SQL qui matche aussi les sous-domaines
        params = {
            "q": f"%.{domain}",
            "output": "json",
        }
        
        response = requests.get(
            CRT_SH_API_URL,
            params=params,
            timeout=timeout,
            headers={"User-Agent": "PENTAGON-OSINT-Agent/1.0"},
        )
        
        if response.status_code != 200:
            result["status"] = "error"
            result["error"] = f"crt.sh HTTP {response.status_code}"
            return result
        
        # Parse la réponse JSON
        certificates_raw = response.json()
        
        if not certificates_raw:
            result["status"] = "success"
            result["error"] = "Aucun certificat trouvé pour ce domaine"
            return result
        
        # Traitement des certificats
        result["total_certificates"] = len(certificates_raw)
        
        subdomains_set: set[str] = set()
        cas_set: set[str] = set()
        all_dates: list[str] = []
        wildcard_count = 0
        
        for cert in certificates_raw:
            # Extraction des sous-domaines depuis "name_value"
            # name_value peut contenir plusieurs domaines séparés par \n
            name_value = cert.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name:
                    if name.startswith("*."):
                        wildcard_count += 1
                    subdomains_set.add(name)
            
            # Extraction de l'autorité de certification
            ca = cert.get("issuer_name", "").strip()
            if ca:
                # Extrait le CN= (Common Name) du CA pour lisibilité
                ca_clean = _extract_ca_name(ca)
                cas_set.add(ca_clean)
            
            # Collecte des dates
            entry_date = cert.get("entry_timestamp")
            if entry_date:
                all_dates.append(entry_date)
        
        # Tri et population du résultat
        result["unique_subdomains"] = sorted(subdomains_set)
        result["certificate_authorities"] = sorted(cas_set)
        
        if all_dates:
            sorted_dates = sorted(all_dates)
            result["first_certificate_date"] = sorted_dates[0]
            result["latest_certificate_date"] = sorted_dates[-1]
        
        # Limite l'export détaillé aux 50 premiers pour ne pas surcharger
        result["certificates"] = [
            _simplify_certificate(c) for c in certificates_raw[:50]
        ]
        
        result["summary"] = {
            "subdomains_count": len(subdomains_set),
            "ca_count": len(cas_set),
            "wildcard_certificates": wildcard_count,
        }
        
    except requests.exceptions.Timeout:
        result["status"] = "error"
        result["error"] = f"Timeout après {timeout}s — crt.sh peut être lent"
    except requests.exceptions.RequestException as e:
        result["status"] = "error"
        result["error"] = f"Erreur réseau : {type(e).__name__}: {str(e)}"
    except ValueError as e:
        result["status"] = "error"
        result["error"] = f"Erreur de parsing JSON : {str(e)}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"
    
    ended_at = datetime.now()
    result["lookup_duration_seconds"] = (ended_at - started_at).total_seconds()
    
    return result


def _extract_ca_name(issuer_string: str) -> str:
    """
    Extrait le nom commun (CN) d'une autorité de certification.
    
    Exemple :
        Input : "C=US, O=Let's Encrypt, CN=R3"
        Output : "Let's Encrypt (R3)"
    """
    parts = {}
    for chunk in issuer_string.split(","):
        chunk = chunk.strip()
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            parts[key.strip()] = value.strip()
    
    o = parts.get("O", "")
    cn = parts.get("CN", "")
    
    if o and cn:
        return f"{o} ({cn})"
    elif cn:
        return cn
    elif o:
        return o
    else:
        return issuer_string[:80]  # fallback tronqué


def _simplify_certificate(cert: dict) -> dict[str, Any]:
    """
    Simplifie un certificat pour l'export, en gardant seulement les champs utiles.
    """
    return {
        "id": cert.get("id"),
        "common_name": cert.get("common_name", ""),
        "name_value": cert.get("name_value", "").split("\n"),
        "issuer": _extract_ca_name(cert.get("issuer_name", "")),
        "not_before": cert.get("not_before"),
        "not_after": cert.get("not_after"),
        "entry_timestamp": cert.get("entry_timestamp"),
    }
