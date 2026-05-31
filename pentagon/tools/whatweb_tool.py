"""
Outil WhatWeb pour PENTAGON.

Cet outil identifie les technologies web utilisées par une cible :
frameworks, serveurs, CMS, librairies JavaScript, CDN, WAF.

Utilisé par : Agent Scanning (PTES phase 3 — Threat Modeling)
Standards :
- OWASP WSTG-INFO-02 (Fingerprint Web Server)
- OWASP WSTG-INFO-08 (Fingerprint Web Application Framework)
- MITRE ATT&CK T1592.002 (Gather Victim Host Information: Software)

Niveau de risque : ACTIF mais très léger (1-3 requêtes seulement).
"""

import json
import subprocess
from datetime import datetime
from typing import Any


# Niveaux d'agressivité de WhatWeb
AGGRESSION_LEVELS = {
    "stealthy": 1,    # 1 requête, infos basiques
    "polite": 3,      # par défaut, équilibré
    "aggressive": 4,  # peut tenter des requêtes ciblées
}


def run_whatweb_scan(
    target_url: str,
    aggression: str = "polite",
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """
    Identifie les technologies web d'une cible avec WhatWeb.
    
    Args:
        target_url: URL de la cible (ex: "https://techshop-vuln.rokina-sylla.me")
        aggression: niveau d'agressivité ("stealthy", "polite", "aggressive").
        timeout_seconds: délai max d'exécution.
    
    Returns:
        Dictionnaire structuré contenant :
        - status: "success" ou "error"
        - target_url: URL scannée
        - http_status: code HTTP retourné par la cible
        - technologies: liste structurée des technologies détectées
        - categories: technologies regroupées par catégorie
                      (server, framework, language, cdn, waf, etc.)
        - sensitive_findings: technologies révélant des versions ou
                              des configurations sensibles
        - inferred_stack: déduction de la stack technique probable
        - duration_seconds: durée d'exécution
        - error: message d'erreur le cas échéant
    """
    started_at = datetime.now()
    aggression_level = AGGRESSION_LEVELS.get(aggression, 3)
    
    result: dict[str, Any] = {
        "status": "success",
        "target_url": target_url,
        "aggression_level": aggression_level,
        "http_status": None,
        "technologies": [],
        "categories": {},
        "sensitive_findings": [],
        "inferred_stack": {},
        "duration_seconds": None,
        "error": None,
    }
    
    # Commande WhatWeb avec sortie JSON
    cmd = [
        "whatweb",
        "--aggression", str(aggression_level),
        "--log-json=-",       # JSON sur stdout
        "--no-errors",        # silence des erreurs réseau
        "--quiet",            # pas de bannière
        target_url,
    ]
    
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        
        if not proc.stdout.strip():
            result["status"] = "error"
            result["error"] = f"WhatWeb n'a retourné aucune sortie. stderr : {proc.stderr[:200]}"
            return result
        
        # Parse la sortie JSON (peut contenir plusieurs lignes JSON)
        parsed = _parse_whatweb_json(proc.stdout)
        
        if not parsed:
            result["status"] = "error"
            result["error"] = "Impossible de parser la sortie JSON de WhatWeb"
            return result
        
        # Extraction des données
        result["http_status"] = parsed.get("http_status")
        result["technologies"] = parsed.get("plugins", [])
        
        # Regroupement par catégorie
        result["categories"] = _categorize_technologies(result["technologies"])
        
        # Identification des findings sensibles
        result["sensitive_findings"] = _identify_sensitive_techs(result["technologies"])
        
        # Inférence de la stack
        result["inferred_stack"] = _infer_stack(result["categories"])
    
    except subprocess.TimeoutExpired:
        result["status"] = "error"
        result["error"] = f"Timeout après {timeout_seconds}s"
    except FileNotFoundError:
        result["status"] = "error"
        result["error"] = "WhatWeb n'est pas installé ou pas dans le PATH"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"
    
    ended_at = datetime.now()
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    
    return result


def _parse_whatweb_json(output: str) -> dict[str, Any] | None:
    """
    Parse la sortie JSON de WhatWeb.
    
    WhatWeb peut retourner plusieurs lignes JSON (une par redirection).
    On prend la dernière (la cible finale).
    """
    # WhatWeb peut wrap la sortie dans des crochets [ ... ]
    output = output.strip()
    if output.startswith("["):
        output = output[1:]
    if output.endswith("]"):
        output = output[:-1]
    
    # Tente de parser comme un tableau JSON valide d'abord
    try:
        data = json.loads(f"[{output}]")
        if data:
            entry = data[-1]
            return _normalize_whatweb_entry(entry)
    except (json.JSONDecodeError, IndexError):
        pass
    
    # Fallback : parsing ligne par ligne
    for line in output.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            entry = json.loads(line)
            return _normalize_whatweb_entry(entry)
        except json.JSONDecodeError:
            continue
    
    return None


def _normalize_whatweb_entry(entry: dict) -> dict[str, Any]:
    """
    Normalise une entrée WhatWeb en structure exploitable.
    
    Format WhatWeb brut :
    {
        "target": "https://...",
        "http_status": 200,
        "plugins": {
            "HTML5": {},
            "HTTPServer": {"string": ["cloudflare"]},
            "Title": {"string": ["TechShop — ..."]},
            ...
        }
    }
    
    Format normalisé :
    {
        "http_status": 200,
        "plugins": [
            {"name": "HTML5", "values": []},
            {"name": "HTTPServer", "values": ["cloudflare"]},
            ...
        ]
    }
    """
    normalized = {
        "http_status": entry.get("http_status"),
        "plugins": [],
    }
    
    plugins_dict = entry.get("plugins", {})
    for name, data in plugins_dict.items():
        values = []
        if isinstance(data, dict):
            # WhatWeb stocke les valeurs dans "string", "version", "account", etc.
            for key in ["string", "version", "account", "module"]:
                if key in data:
                    val = data[key]
                    if isinstance(val, list):
                        values.extend(str(v) for v in val)
                    else:
                        values.append(str(val))
        
        normalized["plugins"].append({
            "name": name,
            "values": values,
        })
    
    return normalized


# Catégorisation des technologies détectées par WhatWeb
TECH_CATEGORIES = {
    "server": ["HTTPServer", "nginx", "Apache", "IIS", "lighttpd"],
    "framework_backend": ["Django", "Rails", "Laravel", "Spring", "Express", "Flask", "ASP.NET"],
    "framework_frontend": ["React", "Vue", "Angular", "Ember", "Backbone"],
    "language": ["PHP", "Python", "Ruby", "Java", "Node.js", "ASP"],
    "cms": ["WordPress", "Drupal", "Joomla", "Magento", "Shopify"],
    "cdn": ["Cloudflare", "Akamai", "Fastly", "CloudFront", "MaxCDN"],
    "waf": ["Cloudflare", "Sucuri", "Incapsula", "ModSecurity"],
    "javascript_lib": ["jQuery", "Bootstrap", "AngularJS", "Modernizr"],
    "hosting": ["Heroku", "Vercel", "Netlify", "AWS", "GCP", "Azure"],
    "analytics": ["Google-Analytics", "Matomo", "Mixpanel"],
    "metadata": ["HTML5", "Title", "Country", "IP", "Email", "MetaGenerator"],
    "headers": ["UncommonHeaders", "X-Frame-Options", "X-Powered-By", "HSTS"],
    "scripts": ["Script", "Cookies"],
}


def _categorize_technologies(techs: list[dict]) -> dict[str, list[dict]]:
    """
    Regroupe les technologies par catégorie.
    """
    categorized = {}
    
    for tech in techs:
        name = tech["name"]
        for category, keywords in TECH_CATEGORIES.items():
            if any(kw.lower() in name.lower() for kw in keywords):
                categorized.setdefault(category, []).append(tech)
                break
        else:
            # Pas de catégorie matchée
            categorized.setdefault("other", []).append(tech)
    
    return categorized


# Technologies considérées comme révélant des infos sensibles
SENSITIVE_INDICATORS = [
    "X-Powered-By",      # révèle PHP/version
    "MetaGenerator",     # révèle CMS/version
    "X-AspNet-Version",  # révèle .NET version
    "Server",            # peut révéler version exacte
]


def _identify_sensitive_techs(techs: list[dict]) -> list[dict[str, Any]]:
    """
    Identifie les technologies qui révèlent des infos sensibles
    (versions précises, identifiants serveur, etc.).
    """
    sensitive = []
    
    for tech in techs:
        name = tech["name"]
        # Détection par nom de technologie sensible
        if any(ind.lower() in name.lower() for ind in SENSITIVE_INDICATORS):
            sensitive.append({
                **tech,
                "reason": f"Révèle des informations techniques détaillées",
            })
        # Détection par présence de numéro de version
        elif tech["values"] and any(_has_version(v) for v in tech["values"]):
            sensitive.append({
                **tech,
                "reason": "Version exacte exposée (utile pour corrélation CVE)",
            })
    
    return sensitive


def _has_version(value: str) -> bool:
    """Détecte si une chaîne contient un numéro de version (ex: '1.24.0')."""
    import re
    return bool(re.search(r"\d+\.\d+", str(value)))


def _infer_stack(categories: dict[str, list]) -> dict[str, Any]:
    """
    Déduit la stack technique probable à partir des catégories détectées.
    """
    stack = {
        "frontend": None,
        "backend": None,
        "server": None,
        "cdn_waf": None,
        "hosting_signals": [],
    }
    
    if "framework_frontend" in categories:
        stack["frontend"] = [t["name"] for t in categories["framework_frontend"]]
    
    if "framework_backend" in categories:
        stack["backend"] = [t["name"] for t in categories["framework_backend"]]
    
    if "server" in categories:
        stack["server"] = [t["name"] for t in categories["server"]]
    
    if "cdn" in categories or "waf" in categories:
        cdn_waf = []
        for cat in ["cdn", "waf"]:
            if cat in categories:
                cdn_waf.extend(t["name"] for t in categories[cat])
        stack["cdn_waf"] = list(set(cdn_waf))
    
    # Détection signaux hosting via headers (Render = rndr-id, etc.)
    for tech in categories.get("headers", []):
        for value in tech.get("values", []):
            value_lower = str(value).lower()
            if "rndr" in value_lower:
                stack["hosting_signals"].append("Render.com (via rndr-id header)")
            elif "vercel" in value_lower:
                stack["hosting_signals"].append("Vercel")
            elif "netlify" in value_lower:
                stack["hosting_signals"].append("Netlify")
            elif "heroku" in value_lower:
                stack["hosting_signals"].append("Heroku")
    
    stack["hosting_signals"] = list(set(stack["hosting_signals"]))
    
    return stack
