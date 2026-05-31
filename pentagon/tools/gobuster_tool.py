"""
Outil Gobuster pour PENTAGON.

Cet outil effectue une énumération de répertoires et fichiers cachés
sur une cible web via brute-force avec wordlist. Permet de découvrir
des endpoints sensibles non référencés (/admin, /api, /.env, etc.).

Utilisé par : Agent Scanning (PTES phase 3 — Threat Modeling)
Standards :
- OWASP WSTG-INFO-08 (Map Application Architecture)
- MITRE ATT&CK T1083 (File and Directory Discovery)
- MITRE ATT&CK T1595.003 (Active Scanning: Wordlist Scanning)

Niveau de risque : ACTIF (émet de nombreuses requêtes vers la cible)
Peut être détecté par les WAF (Cloudflare, etc.) et entraîner un blocage.
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any


# Wordlists disponibles sur Kali
WORDLISTS = {
    "small": "/usr/share/wordlists/dirb/common.txt",                                # ~4 600 mots, rapide
    "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",       # ~87 000 mots
    "large": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",       # ~220 000 mots, long
}

# Codes HTTP considérés comme "trouvés" (existence confirmée)
DEFAULT_STATUS_CODES = "200,204,301,302,307,401,403,500"


def run_gobuster_scan(
    target_url: str,
    wordlist: str = "small",
    extensions: str | None = "php,html,txt,bak,old,env,git",
    threads: int = 20,
    timeout_seconds: int = 600,
    status_codes: str = DEFAULT_STATUS_CODES,
    exclude_length: str | None = None, 
) -> dict[str, Any]:
    """
    Effectue une énumération de répertoires Gobuster sur une cible web.
    
    Args:
        target_url: URL de base à scanner (ex: "https://techshop-vuln.rokina-sylla.me")
        wordlist: clé de WORDLISTS ("small", "medium", "large") ou chemin custom.
        extensions: extensions à tester en plus des répertoires (ex: "php,html,env").
                    Mettre None pour désactiver.
        threads: nombre de threads concurrents (par défaut 20).
        timeout_seconds: délai max total pour le scan.
        status_codes: codes HTTP à considérer comme "trouvés".
    
    Returns:
        Dictionnaire structuré contenant :
        - status: "success", "partial" ou "error"
        - target_url: URL scannée
        - wordlist_used: chemin de la wordlist
        - wordlist_size: nombre de mots dans la wordlist
        - findings: liste des endpoints découverts avec leur code HTTP
        - findings_count: nombre d'endpoints trouvés
        - findings_by_status: dict {status_code: [paths]}
        - sensitive_findings: liste des findings considérés comme sensibles
        - duration_seconds: durée totale
        - error: message d'erreur le cas échéant
    """
    started_at = datetime.now()
    
    result: dict[str, Any] = {
        "status": "success",
        "target_url": target_url,
        "wordlist_used": None,
        "wordlist_size": 0,
        "extensions_tested": extensions,
        "threads_used": threads,
        "findings": [],
        "findings_count": 0,
        "findings_by_status": {},
        "sensitive_findings": [],
        "duration_seconds": None,
        "error": None,
    }
    
    # Résolution du chemin de la wordlist
    wordlist_path = WORDLISTS.get(wordlist, wordlist)
    if not Path(wordlist_path).exists():
        result["status"] = "error"
        result["error"] = f"Wordlist introuvable : {wordlist_path}"
        return result
    
    result["wordlist_used"] = wordlist_path
    result["wordlist_size"] = _count_lines(wordlist_path)
    
    # Construction de la commande Gobuster
    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", wordlist_path,
        "-t", str(threads),
        "-s", status_codes,
        "-b", "",                          # ne pas filtrer sur statuts (override default)
        "--no-error",                      # silence les erreurs réseau individuelles
        "-q",                              # mode quiet (moins verbeux)
        "-k",                              # ignorer les erreurs SSL
    ]
    
    if extensions:
        cmd.extend(["-x", extensions])
    # Filtre les réponses par taille (utile pour les SPA qui retournent
    # le même index.html pour toutes les URLs invalides)
    if exclude_length:
        cmd.extend(["--exclude-length", exclude_length])
    
    try:
        # Exécution de Gobuster en sous-processus
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        
        # Parse la sortie standard
        findings = _parse_gobuster_output(proc.stdout)
        result["findings"] = findings
        result["findings_count"] = len(findings)
        
        # Regroupement par code HTTP
        for finding in findings:
            status = str(finding["status_code"])
            result["findings_by_status"].setdefault(status, []).append(finding["path"])
        
        # Identification des findings sensibles
        result["sensitive_findings"] = _identify_sensitive_findings(findings)
        
        # Si Gobuster a retourné une erreur mais on a quand même des findings
        if proc.returncode != 0 and findings:
            result["status"] = "partial"
            result["error"] = f"Gobuster a retourné code {proc.returncode} mais a produit des résultats"
        elif proc.returncode != 0 and not findings:
            result["status"] = "error"
            result["error"] = f"Gobuster a échoué (code {proc.returncode}) : {proc.stderr[:300]}"
    
    except subprocess.TimeoutExpired:
        result["status"] = "error"
        result["error"] = f"Timeout après {timeout_seconds}s"
    except FileNotFoundError:
        result["status"] = "error"
        result["error"] = "Gobuster n'est pas installé ou pas dans le PATH"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"
    
    ended_at = datetime.now()
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    
    return result


def _count_lines(filepath: str) -> int:
    """Compte le nombre de lignes d'un fichier (taille de la wordlist)."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def _parse_gobuster_output(output: str) -> list[dict[str, Any]]:
    """
    Parse la sortie texte de Gobuster en mode quiet (-q).
    
    Format typique :
        /admin                (Status: 401) [Size: 1234]
        /login                (Status: 200) [Size: 5678]
        /api                  (Status: 200) [Size: 234] [--> /api/]
    """
    findings = []
    
    for line in output.splitlines():
        line = line.strip()
        if not line or "Status:" not in line:
            continue
        
        # Extrait le chemin (avant "(Status:")
        try:
            path_part, rest = line.split("(Status:", 1)
            path = path_part.strip()
            
            # Extrait le code de statut
            status_part = rest.split(")", 1)[0].strip()
            status_code = int(status_part)
            
            # Extrait la taille si présente
            size = None
            if "[Size:" in rest:
                size_part = rest.split("[Size:", 1)[1].split("]", 1)[0].strip()
                try:
                    size = int(size_part)
                except ValueError:
                    pass
            
            # Extrait la redirection si présente
            redirect = None
            if "[-->" in rest:
                redirect = rest.split("[-->", 1)[1].split("]", 1)[0].strip()
            
            findings.append({
                "path": path,
                "status_code": status_code,
                "size_bytes": size,
                "redirect_to": redirect,
            })
        except (ValueError, IndexError):
            # Ligne mal formée, on l'ignore silencieusement
            continue
    
    return findings


# Liste de paths "sensibles" connus pour leur valeur pentest
SENSITIVE_PATTERNS = [
    # Configuration & secrets
    ".env", ".git", ".svn", ".htaccess", ".htpasswd", "wp-config",
    "config", "settings", "credentials", "secrets",
    # Admin & management
    "admin", "administrator", "manage", "manager", "phpmyadmin",
    "actuator",     # Spring Boot Actuator (très sensible !)
    "console",
    # API & dev
    "api", "swagger", "openapi", "graphql", "v1", "v2",
    "debug", "test", "dev", "staging",
    # Backups & dumps
    "backup", "bak", "old", "dump", "sql",
    # Auth
    "login", "auth", "oauth", "register", "signup", "logout",
    # Spring Boot specific
    "actuator/env", "actuator/health", "actuator/info",
    "actuator/mappings", "actuator/beans",
]


def _identify_sensitive_findings(findings: list[dict]) -> list[dict[str, Any]]:
    """
    Identifie parmi les findings ceux qui correspondent à des paths sensibles.
    
    Retourne les findings enrichis avec un champ "sensitivity_reason".
    """
    sensitive = []
    
    for finding in findings:
        path_lower = finding["path"].lower()
        
        for pattern in SENSITIVE_PATTERNS:
            if pattern in path_lower:
                sensitive.append({
                    **finding,
                    "sensitivity_reason": f"Match pattern sensible : '{pattern}'",
                })
                break  # un seul match suffit
    
    return sensitive
