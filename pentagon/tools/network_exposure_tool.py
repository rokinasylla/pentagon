"""
Outil d'analyse de l'exposition réseau pour PENTAGON.

Enrichit la sortie de Nmap (déjà collectée par l'agent Scanning) pour signaler
les **services risqués exposés** sur Internet — une famille de vulnérabilités
EN DEHORS de l'OWASP Top 10 applicatif (surface réseau / configuration) :

- Bases de données exposées (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch…)
  qui ne devraient JAMAIS être joignables depuis Internet.
- Accès distants (RDP, VNC, Telnet, FTP) et protocoles en CLAIR (FTP/Telnet).
- Services d'administration/management exposés (Docker API, Webmin, SMB, NFS,
  panneaux d'admin sur ports alternatifs).

C'est une **fonction PURE** : elle n'émet aucun trafic (elle analyse les
résultats Nmap existants) → 100% testable hors-ligne, aucune dépendance.

Utilisé par : Agent Scanning (PTES phase 3-4).
Standards :
- OWASP WSTG-INFO-02, A05:2021 (Security Misconfiguration)
- MITRE ATT&CK T1046 (Network Service Discovery)
- CWE-668 (Exposure of Resource to Wrong Sphere), CWE-200
"""

from typing import Any


# Ports normaux pour un service web (non signalés comme exposition risquée).
WEB_PORTS = {80, 443}

# Ports risqués : {port: (libellé, sévérité, raison)}
RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("FTP", "high", "Transfert de fichiers en CLAIR (identifiants interceptables)"),
    23: ("Telnet", "high", "Administration à distance en CLAIR (obsolète)"),
    25: ("SMTP", "medium", "Serveur mail exposé (risque de relais ouvert)"),
    110: ("POP3", "medium", "Récupération de mail en clair"),
    135: ("MSRPC", "medium", "Endpoint RPC Windows exposé"),
    139: ("NetBIOS", "high", "Partage Windows exposé"),
    143: ("IMAP", "medium", "Récupération de mail en clair"),
    389: ("LDAP", "medium", "Annuaire exposé"),
    445: ("SMB", "high", "Partage de fichiers Windows exposé (surface critique)"),
    512: ("rexec", "high", "Service d'exécution distante obsolète"),
    513: ("rlogin", "high", "Login distant en clair obsolète"),
    1433: ("MSSQL", "high", "Base de données SQL Server exposée"),
    1521: ("Oracle DB", "high", "Base de données Oracle exposée"),
    2049: ("NFS", "high", "Partage de fichiers réseau exposé"),
    2375: ("Docker API", "high", "API Docker NON chiffrée exposée (prise de contrôle hôte)"),
    2376: ("Docker API TLS", "high", "API Docker exposée"),
    3306: ("MySQL", "high", "Base de données MySQL exposée"),
    3389: ("RDP", "high", "Bureau à distance Windows exposé"),
    4444: ("metasploit?", "medium", "Port souvent utilisé par des backdoors"),
    5432: ("PostgreSQL", "high", "Base de données PostgreSQL exposée"),
    5900: ("VNC", "high", "Bureau à distance VNC exposé"),
    5984: ("CouchDB", "high", "Base de données CouchDB exposée"),
    6379: ("Redis", "high", "Cache Redis exposé (souvent sans authentification)"),
    7001: ("WebLogic", "high", "Serveur d'applications exposé (cibles RCE connues)"),
    9042: ("Cassandra", "high", "Base de données Cassandra exposée"),
    9200: ("Elasticsearch", "high", "Elasticsearch exposé (souvent sans authentification)"),
    10000: ("Webmin", "high", "Panneau d'administration Webmin exposé"),
    11211: ("Memcached", "high", "Memcached exposé (amplification DDoS, pas d'auth)"),
    27017: ("MongoDB", "high", "Base de données MongoDB exposée"),
}

# Services risqués repérés par NOM (si sur un port non standard).
RISKY_SERVICE_NAMES = {
    "ftp": "high", "telnet": "high", "mysql": "high", "postgresql": "high",
    "mongodb": "high", "redis": "high", "ms-sql-s": "high", "microsoft-ds": "high",
    "netbios-ssn": "high", "vnc": "high", "ms-wbt-server": "high", "rdp": "high",
    "elasticsearch": "high", "memcached": "high", "oracle-tns": "high",
    "nfs": "high", "docker": "high", "smtp": "medium", "ldap": "medium",
}

# Ports d'administration/management sur alternatives HTTP (confiance moindre).
ADMIN_ALT_PORTS = {8080, 8000, 8081, 8443, 8888, 9000, 9090, 7001, 7070}

# CDN/WAF : ces services ouvrent des ports alt-HTTP standards (ex. Cloudflare
# 8080/8443) qui NE sont PAS des panneaux d'admin de la cible → à ne pas signaler.
CDN_MARKERS = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "sucuri")

# Mots-clés de panneaux d'administration dans le produit/service détecté.
ADMIN_PANEL_KEYWORDS = (
    "webmin", "phpmyadmin", "adminer", "jenkins", "grafana", "kibana",
    "tomcat", "manager", "portainer", "cockpit", "zabbix", "pgadmin",
)

# Protocoles en clair (confidentialité nulle).
CLEARTEXT_SERVICES = {"ftp", "telnet", "http", "pop3", "imap", "smtp"}


def _f(fid: str, title: str, severity: str, evidence: str, standard: str) -> dict[str, Any]:
    return {"id": fid, "title": title, "severity": severity,
            "evidence": evidence, "standard": standard}


def analyze_network_exposure(nmap_data: dict[str, Any]) -> dict[str, Any]:
    """
    Analyse les résultats Nmap pour signaler les services risqués exposés.

    Args:
        nmap_data: dict renvoyé par run_nmap_scan (clé 'hosts' → ports ouverts).

    Returns:
        {
          "status": "success" | "error",
          "open_ports_total": int,
          "exposed_services": [{host, port, service, product, version,
                                severity, reason}],
          "findings": [{id, title, severity, evidence, standard}],
          "error": "..."
        }
    """
    result: dict[str, Any] = {
        "status": "success",
        "open_ports_total": 0,
        "exposed_services": [],
        "findings": [],
        "error": None,
    }

    if not isinstance(nmap_data, dict) or nmap_data.get("status") == "error":
        result["status"] = "error"
        result["error"] = "Données Nmap indisponibles ou en erreur."
        return result

    findings: list[dict[str, Any]] = []
    hosts = nmap_data.get("hosts", {}) or {}

    for host, host_data in hosts.items():
        for p in (host_data or {}).get("ports", []):
            if p.get("state") != "open":
                continue
            result["open_ports_total"] += 1
            port = p.get("port")
            service = (p.get("service") or "").lower()
            product = (p.get("product") or "")
            version = (p.get("version") or "")
            prod_low = f"{product} {service}".lower()

            is_cdn = any(m in prod_low for m in CDN_MARKERS)
            severity = None
            reason = None
            label = service or str(port)

            # 1) Port risqué connu.
            if port in RISKY_PORTS:
                label, severity, reason = RISKY_PORTS[port]
            # 2) Service risqué par nom (port non standard).
            elif service in RISKY_SERVICE_NAMES:
                severity = RISKY_SERVICE_NAMES[service]
                reason = f"Service sensible '{service}' exposé sur le port {port}"
            # 3) Port HTTP alternatif.
            elif port in ADMIN_ALT_PORTS and port not in WEB_PORTS:
                if is_cdn:
                    # Port alt-HTTP standard d'un CDN (ex. Cloudflare) → pas une
                    # exposition de la cible : on n'émet aucun finding.
                    continue
                # Sans indice d'admin, un port alt-HTTP ouvert est informatif.
                severity = "low"
                reason = f"Port HTTP alternatif ouvert ({port})"
                label = f"alt-http/{service or port}"

            # 4) Panneau d'administration détecté par produit.
            if any(k in prod_low for k in ADMIN_PANEL_KEYWORDS):
                severity = severity or "medium"
                reason = (reason or "") + f" — panneau d'admin détecté ({product.strip()})"

            if severity:
                entry = {
                    "host": host, "port": port, "service": service,
                    "product": product, "version": version,
                    "severity": severity, "reason": reason.strip(" —"),
                }
                result["exposed_services"].append(entry)
                ver = f" {product} {version}".strip()
                findings.append(_f(
                    f"net-exposed-{port}",
                    f"Service risqué exposé : {label} (port {port})",
                    severity,
                    f"{host}:{port}{(' — ' + ver) if ver else ''} — {entry['reason']}",
                    "WSTG-INFO-02 / CWE-668 / T1046"))

            # 5) Protocole en clair (hors HTTP 80 standard, trop courant).
            if service in CLEARTEXT_SERVICES and service != "http" and port not in WEB_PORTS:
                findings.append(_f(
                    f"net-cleartext-{port}",
                    f"Protocole en clair exposé : {service} (port {port})",
                    "medium" if service in ("smtp", "pop3", "imap") else "high",
                    f"{host}:{port} — données transmises sans chiffrement",
                    "WSTG-CRYP / CWE-319"))

    result["findings"] = findings
    return result


if __name__ == "__main__":
    import json
    import sys
    # Démo : lit un JSON Nmap depuis un fichier, ou utilise un exemple.
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = {"status": "success", "hosts": {"demo": {"ports": [
            {"port": 3306, "state": "open", "service": "mysql", "product": "MySQL", "version": "8.0"},
            {"port": 23, "state": "open", "service": "telnet", "product": "", "version": ""},
            {"port": 443, "state": "open", "service": "https", "product": "nginx", "version": ""},
        ]}}}
    print(json.dumps(analyze_network_exposure(data), indent=2, ensure_ascii=False, default=str))
