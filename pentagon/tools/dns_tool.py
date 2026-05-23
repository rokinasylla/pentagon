"""
Outil DNS Lookup pour PENTAGON.

Cet outil interroge les serveurs DNS publics pour récupérer les
enregistrements d'un domaine : A, AAAA, MX, NS, TXT, CNAME, SOA.

Utilisé par : Agent OSINT (PTES phase 2 — Intelligence Gathering)
Standards : OWASP WSTG-INFO-04, MITRE ATT&CK T1590.002, T1596.001
"""

import dns.resolver
import dns.exception
from typing import Any


# Types d'enregistrements DNS à interroger par défaut
DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def run_dns_lookup(
    domain: str,
    record_types: list[str] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """
    Effectue un DNS lookup complet sur un domaine.
    
    Args:
        domain: nom de domaine à interroger (ex: "techshop-vuln.rokina-sylla.me")
        record_types: types d'enregistrements à requêter. Si None, utilise
                      les types par défaut (A, AAAA, MX, NS, TXT, CNAME, SOA).
        timeout: délai d'attente max par requête en secondes.
    
    Returns:
        Un dictionnaire structuré contenant :
        - status: "success", "partial", ou "error"
        - domain: le domaine interrogé
        - records: dict {type: [values]} pour chaque type trouvé
        - errors: dict {type: error_message} pour les types en erreur
        - inferred_hosting: hébergeur déduit des CNAME (Render, Vercel, etc.)
    """
    if record_types is None:
        record_types = DEFAULT_RECORD_TYPES
    
    result: dict[str, Any] = {
        "status": "success",
        "domain": domain,
        "records": {},
        "errors": {},
        "inferred_hosting": None,
    }
    
    # Configure le resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    
    # Interroge chaque type d'enregistrement
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            values = [_format_record(answer, record_type) for answer in answers]
            result["records"][record_type] = values
        except dns.resolver.NoAnswer:
            # Le domaine existe mais pas de record de ce type — pas une erreur
            pass
        except dns.resolver.NXDOMAIN:
            # Le domaine n'existe pas — erreur grave, on arrête
            result["status"] = "error"
            result["errors"]["NXDOMAIN"] = f"Le domaine '{domain}' n'existe pas"
            return result
        except dns.exception.Timeout:
            result["errors"][record_type] = "Timeout"
            result["status"] = "partial"
        except Exception as e:
            result["errors"][record_type] = f"{type(e).__name__}: {str(e)}"
            result["status"] = "partial"
    
    # Tente de déduire l'hébergeur à partir des CNAME et A records
    result["inferred_hosting"] = _infer_hosting_provider(result["records"])
    
    return result


def _format_record(answer: Any, record_type: str) -> str:
    """
    Formate un enregistrement DNS en chaîne lisible.
    
    Args:
        answer: l'objet réponse DNS.
        record_type: le type d'enregistrement (A, MX, etc.)
    
    Returns:
        La valeur de l'enregistrement sous forme de chaîne.
    """
    if record_type == "MX":
        # MX : "10 mail.example.com" (préférence + serveur)
        return f"{answer.preference} {answer.exchange}"
    elif record_type == "SOA":
        # SOA : serveur primaire (le plus informatif)
        return f"{answer.mname} (admin: {answer.rname})"
    elif record_type == "TXT":
        # TXT : peut être bytes, on décode
        if isinstance(answer.strings, (list, tuple)):
            return " ".join(s.decode() if isinstance(s, bytes) else str(s) for s in answer.strings)
        return str(answer)
    else:
        # A, AAAA, NS, CNAME : représentation directe
        return str(answer)


def _infer_hosting_provider(records: dict[str, list[str]]) -> str | None:
    """
    Tente de deviner l'hébergeur à partir des enregistrements DNS.
    
    C'est une heuristique simple basée sur les CNAME et NS connus.
    """
    # Signatures connues d'hébergeurs (CNAME ou NS contenant ces termes)
    hosting_signatures = {
        "Render.com": ["onrender.com", "render.com"],
        "Vercel": ["vercel.app", "vercel-dns"],
        "Netlify": ["netlify.app", "netlify.com"],
        "GitHub Pages": ["github.io", "pages.github.com"],
        "Cloudflare": ["cloudflare.com", "cloudflare.net"],
        "AWS": ["amazonaws.com", "awsdns"],
        "Google Cloud": ["googleusercontent.com", "googledomains.com"],
        "Azure": ["azurewebsites.net", "azure.com"],
        "Heroku": ["herokuapp.com", "heroku"],
    }
    
    # Concatène tous les enregistrements pertinents
    haystack_parts = []
    for record_type in ["CNAME", "NS", "A"]:
        if record_type in records:
            haystack_parts.extend(records[record_type])
    haystack = " ".join(haystack_parts).lower()
    
    # Cherche une signature
    for provider, signatures in hosting_signatures.items():
        if any(sig.lower() in haystack for sig in signatures):
            return provider
    
    return None

