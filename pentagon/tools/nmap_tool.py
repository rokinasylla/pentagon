"""
Outil Nmap pour PENTAGON.

Cet outil effectue un scan de ports actif sur une cible et retourne
les services exposés, leurs versions, et l'OS détecté si possible.

Utilisé par : Agent Scanning (PTES phase 3 — Threat Modeling)
Standards : OWASP WSTG-INFO-02, MITRE ATT&CK T1046 (Network Service Discovery)

ATTENTION : cet outil émet du trafic ACTIF vers la cible.
Il doit être invoqué uniquement après validation des Rules of Engagement (RoE).
"""

import logging
import nmap
from datetime import datetime, timezone
from typing import Any

# Silence les warnings verbeux de python-nmap
logging.getLogger("nmap").setLevel(logging.CRITICAL)


# Profils de scan préconfigurés
SCAN_PROFILES = {
    "quick": {
        "ports": "80,443,22,21,25,3306,8080,8443",
        "arguments": "-sV -T4 --version-intensity 5",
        "description": "Scan rapide des ports les plus communs",
    },
    "standard": {
        "ports": "1-1000",
        "arguments": "-sV -T3 --version-intensity 7",
        "description": "Scan complet des 1000 premiers ports avec détection de versions",
    },
    "web_focused": {
        "ports": "80,443,8000,8080,8443,8888,3000,5000,8081,9000",
        "arguments": "-sV -sC -T3",
        "description": "Scan ciblé sur les ports web avec scripts par défaut",
    },
    "full": {
        "ports": "1-65535",
        "arguments": "-sV -T3",
        "description": "Scan exhaustif de tous les ports (long)",
    },
}


def run_nmap_scan(
    target: str,
    profile: str = "web_focused",
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """
    Effectue un scan Nmap sur une cible.
    
    Args:
        target: hôte cible (domaine ou IP) — ex: "techshop-vuln.rokina-sylla.me"
        profile: profil de scan parmi SCAN_PROFILES ("quick", "standard", 
                 "web_focused", "full"). Par défaut "web_focused".
        timeout_seconds: délai d'attente maximum pour le scan.
    
    Returns:
        Un dictionnaire structuré contenant :
        - status: "success" ou "error"
        - target: cible scannée
        - profile_used: profil de scan utilisé
        - scan_start: timestamp de début
        - scan_end: timestamp de fin
        - duration_seconds: durée totale
        - hosts: dict {host: {state, hostnames, ports: [...]}}
        - summary: résumé chiffré (nombre de hosts, ports ouverts, services détectés)
        - error: message d'erreur le cas échéant
    """
    if profile not in SCAN_PROFILES:
        return {
            "status": "error",
            "target": target,
            "error": f"Profil inconnu : '{profile}'. Disponibles : {list(SCAN_PROFILES.keys())}",
        }
    
    config = SCAN_PROFILES[profile]
    started_at = datetime.now(timezone.utc)
    
    result: dict[str, Any] = {
        "status": "success",
        "target": target,
        "profile_used": profile,
        "profile_description": config["description"],
        "scan_start": started_at.isoformat(),
        "scan_end": None,
        "duration_seconds": None,
        "hosts": {},
        "summary": {
            "hosts_scanned": 0,
            "hosts_up": 0,
            "open_ports_total": 0,
            "services_detected": [],
        },
        "error": None,
    }
    
    try:
        scanner = nmap.PortScanner()
        
        # Exécute le scan
        scanner.scan(
            hosts=target,
            ports=config["ports"],
            arguments=config["arguments"],
            timeout=timeout_seconds,
        )
        
        # Parse les résultats par hôte
        for host in scanner.all_hosts():
            host_data = _parse_host_data(scanner, host)
            result["hosts"][host] = host_data
            
            result["summary"]["hosts_scanned"] += 1
            if host_data["state"] == "up":
                result["summary"]["hosts_up"] += 1
            
            for port_info in host_data["ports"]:
                if port_info["state"] == "open":
                    result["summary"]["open_ports_total"] += 1
                    service_name = port_info.get("service", "")
                    if service_name and service_name not in result["summary"]["services_detected"]:
                        result["summary"]["services_detected"].append(service_name)
    
    except nmap.PortScannerError as e:
        result["status"] = "error"
        result["error"] = f"Nmap erreur : {str(e)}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"
    
    ended_at = datetime.now(timezone.utc)
    result["scan_end"] = ended_at.isoformat()
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    
    return result


def _parse_host_data(scanner: nmap.PortScanner, host: str) -> dict[str, Any]:
    """
    Extrait les données pertinentes pour un hôte donné.
    
    Args:
        scanner: l'instance PortScanner de nmap.
        host: l'hôte à analyser.
    
    Returns:
        Dict structuré avec l'état, hostnames, et ports détaillés.
    """
    host_info = {
        "state": scanner[host].state(),
        "hostnames": [h.get("name", "") for h in scanner[host].hostnames()],
        "addresses": scanner[host].get("addresses", {}),
        "ports": [],
    }
    
    # Parse chaque protocole (tcp, udp)
    for protocol in scanner[host].all_protocols():
        ports = scanner[host][protocol].keys()
        
        for port in ports:
            port_data = scanner[host][protocol][port]
            host_info["ports"].append({
                "port": int(port),
                "protocol": protocol,
                "state": port_data.get("state", ""),
                "service": port_data.get("name", ""),
                "product": port_data.get("product", ""),
                "version": port_data.get("version", ""),
                "extra_info": port_data.get("extrainfo", ""),
                "cpe": port_data.get("cpe", ""),
            })
    
    return host_info
