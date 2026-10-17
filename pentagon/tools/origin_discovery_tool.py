"""
Outil de découverte d'IP d'origine pour PENTAGON.

Objectif défensif : Cloudflare agit en proxy inverse devant le vrai serveur.
Si ce serveur d'origine reste joignable EN DIRECT (par son IP), toute la
protection Cloudflare (WAF, anti-DDoS, TLS géré) peut être contournée en
s'adressant à l'IP au lieu du domaine. C'est une **misconfiguration classique
et à fort impact** — exactement le type de finding qu'un pentest doit remonter.

Cet outil ne « casse » rien : il fait de la reconnaissance (technique
Origin IP Leak / OSINT) puis, en phase active et sous réserve du RoE, il
VÉRIFIE si une IP candidate sert bien l'application en direct.

Deux étages, séparés par leur niveau de risque :
1. PASSIF (run_origin_discovery) : agrège des IP candidates depuis les sources
   publiques déjà utilisées par PENTAGON (crt.sh, DNS A/MX), puis classe
   chaque IP « Cloudflare » vs « hors-Cloudflare ». Une IP hors-Cloudflare
   trouvée dans les certificats/DNS de la cible est une piste d'origine.
2. ACTIF (verify_origin_exposure) : confirme (ou infirme) l'exposition en
   comparant la réponse servie par l'IP directe à celle servie via le domaine
   fronté. À n'exécuter que sur une IP autorisée par le RoE (active_scan).

Utilisé par : Agent OSINT (étage passif) et Agent Scanning (étage actif).
Standards :
- MITRE ATT&CK T1590.005 (Gather Victim Network Information: IP Addresses)
- OWASP WSTG-INFO-04 (Enumerate Applications on Webserver)
- OWASP A05:2021 (Security Misconfiguration)
"""

import ipaddress
from datetime import datetime, timezone
from typing import Any

import requests

from pentagon.tools.crtsh_tool import run_crtsh_lookup
from pentagon.tools.waf_detector_tool import BODY_SNIPPET_LEN


DEFAULT_TIMEOUT = 15
DEFAULT_HEADERS = {"User-Agent": "PENTAGON-Origin-Discovery/1.0"}

# Plages IPv4 publiées par Cloudflare (source : https://www.cloudflare.com/ips-v4).
# Toute IP dans ces plages est une IP de bordure Cloudflare, PAS une origine.
CLOUDFLARE_IPV4_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

_CLOUDFLARE_NETWORKS = [ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_IPV4_RANGES]


def is_cloudflare_ip(ip: str) -> bool:
    """
    Indique (PUR) si une IP appartient aux plages publiées par Cloudflare.

    Une IP invalide ou IPv6 hors périmètre renvoie False (on ne la classe pas
    comme Cloudflare faute de preuve).
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return False

    return any(addr in network for network in _CLOUDFLARE_NETWORKS)


def classify_ips(ips: list[str]) -> dict[str, list[str]]:
    """
    Répartit (PUR) une liste d'IP en trois catégories.

    Returns:
        {
          "cloudflare":     IP appartenant aux plages Cloudflare (bordure),
          "non_cloudflare": IP valides hors Cloudflare (candidates d'origine),
          "invalid":        chaînes non parsables comme IP,
        }
    Chaque liste est dédupliquée en conservant l'ordre d'apparition.
    """
    seen: set[str] = set()
    cloudflare: list[str] = []
    non_cloudflare: list[str] = []
    invalid: list[str] = []

    for raw in ips:
        ip = (raw or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            invalid.append(ip)
            continue

        if is_cloudflare_ip(ip):
            cloudflare.append(ip)
        else:
            non_cloudflare.append(ip)

    return {
        "cloudflare": cloudflare,
        "non_cloudflare": non_cloudflare,
        "invalid": invalid,
    }


def _extract_title(html: str) -> str | None:
    """Extrait grossièrement le <title> d'une page (sans dépendance externe)."""
    if not html:
        return None
    lower = html.lower()
    start = lower.find("<title")
    if start == -1:
        return None
    gt = lower.find(">", start)
    end = lower.find("</title>", gt)
    if gt == -1 or end == -1:
        return None
    return html[gt + 1:end].strip() or None


def compare_responses(front: dict[str, Any], origin: dict[str, Any]) -> dict[str, Any]:
    """
    Compare (PUR) la réponse « domaine fronté » et la réponse « IP directe »
    pour décider si l'IP sert la MÊME application (donc origine exposée).

    Chaque réponse est un dict : {status, title, server, body_len, body_snippet}.

    Heuristique par signaux concordants (chacun renforce la confiance) :
    - même code HTTP de succès (2xx),
    - même <title>,
    - tailles de corps proches (< 15 % d'écart),
    - le corps direct ne ressemble pas à une page de blocage Cloudflare.

    Returns:
        {"same_app": bool, "confidence": float 0..1, "signals": [str]}
    """
    signals: list[str] = []
    score = 0.0

    f_status = front.get("status")
    o_status = origin.get("status")
    if isinstance(o_status, int) and 200 <= o_status < 300:
        if f_status == o_status:
            score += 0.3
            signals.append(f"Même code HTTP {o_status}")
        else:
            score += 0.15
            signals.append(f"Origine répond en 2xx ({o_status})")

    f_title = front.get("title")
    o_title = origin.get("title")
    if f_title and o_title and f_title.strip().lower() == o_title.strip().lower():
        score += 0.4
        signals.append(f"Même <title> : « {o_title[:60]} »")

    f_len = front.get("body_len") or 0
    o_len = origin.get("body_len") or 0
    if f_len and o_len:
        larger = max(f_len, o_len)
        delta = abs(f_len - o_len) / larger if larger else 1.0
        if delta < 0.15:
            score += 0.2
            signals.append(f"Tailles de corps proches ({f_len} vs {o_len} octets)")

    # Si la réponse directe est elle-même une page Cloudflare, ce n'est PAS
    # une origine exposée (l'IP est encore de la bordure).
    o_snippet = (origin.get("body_snippet") or "").lower()
    if "cloudflare" in o_snippet or "cf-ray" in o_snippet:
        score -= 0.3
        signals.append("Réponse directe encore estampillée Cloudflare (pas une origine)")

    o_server = (origin.get("server") or "").lower()
    if o_server and "cloudflare" not in o_server:
        score += 0.1
        signals.append(f"En-tête Server direct : {origin.get('server')}")

    confidence = max(0.0, min(1.0, score))
    return {
        "same_app": confidence >= 0.6,
        "confidence": round(confidence, 2),
        "signals": signals,
    }


def _resolve_a_records(hostname: str, timeout: float = 5.0) -> list[str]:
    """Résout les enregistrements A d'un hôte. Retourne [] en cas d'échec."""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(hostname, "A")
        return [str(a) for a in answers]
    except Exception:
        return []


def run_origin_discovery(
    domain: str,
    extra_subdomains: list[str] | None = None,
    max_hosts: int = 25,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Étage PASSIF : agrège et classe les IP candidates d'origine d'un domaine.

    Sources (toutes passives, déjà utilisées par PENTAGON) :
    - crt.sh : sous-domaines historiques (certificats), souvent oubliés et
      parfois hébergés hors Cloudflare,
    - résolution DNS A de la cible et des sous-domaines découverts,
    - enregistrements MX (les serveurs mail pointent fréquemment vers l'IP
      d'origine réelle).

    NE fait AUCUNE requête vers le serveur web de la cible : reste dans le
    périmètre « reconnaissance passive » de l'agent OSINT.

    Args:
        domain: domaine cible (ex: "techshop-vuln.rokina-sylla.me").
        extra_subdomains: sous-domaines supplémentaires à résoudre (optionnel).
        max_hosts: plafond d'hôtes résolus (évite l'explosion sur gros domaines).
        timeout: délai réseau par requête.

    Returns:
        Dict : status, domain, candidates (IP -> hôtes source), classification
        (cloudflare / non_cloudflare / invalid), likely_origins (IP hors-CF),
        sources, error.
    """
    started_at = datetime.now(timezone.utc)

    result: dict[str, Any] = {
        "status": "success",
        "domain": domain,
        "hosts_resolved": [],
        "ip_to_hosts": {},
        "classification": {"cloudflare": [], "non_cloudflare": [], "invalid": []},
        "likely_origins": [],
        "sources": {"crtsh_subdomains": 0, "hosts_queried": 0},
        "duration_seconds": None,
        "error": None,
    }

    try:
        hosts: list[str] = [domain]

        # 1. Sous-domaines via crt.sh (certificats).
        crt = run_crtsh_lookup(domain, timeout=timeout)
        if crt.get("status") == "success":
            subs = [
                s.lstrip("*.").strip()
                for s in crt.get("unique_subdomains", [])
                if s and not s.startswith("*.")
            ]
            result["sources"]["crtsh_subdomains"] = len(subs)
            hosts.extend(subs)

        if extra_subdomains:
            hosts.extend(extra_subdomains)

        # Dédupe en conservant l'ordre, puis plafonne.
        seen: set[str] = set()
        unique_hosts: list[str] = []
        for h in hosts:
            h = h.strip().lower()
            if h and h not in seen:
                seen.add(h)
                unique_hosts.append(h)
        unique_hosts = unique_hosts[:max_hosts]

        # 2. Résolution A de chaque hôte + MX du domaine principal.
        ip_to_hosts: dict[str, list[str]] = {}
        for host in unique_hosts:
            for ip in _resolve_a_records(host, timeout=min(timeout, 5)):
                ip_to_hosts.setdefault(ip, [])
                if host not in ip_to_hosts[ip]:
                    ip_to_hosts[ip].append(host)

        for mx_host in _resolve_mx_hosts(domain, timeout=min(timeout, 5)):
            for ip in _resolve_a_records(mx_host, timeout=min(timeout, 5)):
                ip_to_hosts.setdefault(ip, [])
                label = f"MX:{mx_host}"
                if label not in ip_to_hosts[ip]:
                    ip_to_hosts[ip].append(label)

        result["hosts_resolved"] = unique_hosts
        result["ip_to_hosts"] = ip_to_hosts
        result["sources"]["hosts_queried"] = len(unique_hosts)

        # 3. Classification Cloudflare vs hors-Cloudflare.
        classification = classify_ips(list(ip_to_hosts.keys()))
        result["classification"] = classification
        result["likely_origins"] = [
            {"ip": ip, "seen_on": ip_to_hosts.get(ip, [])}
            for ip in classification["non_cloudflare"]
        ]

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"

    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    return result


def _resolve_mx_hosts(domain: str, timeout: float = 5.0) -> list[str]:
    """Retourne les hôtes MX d'un domaine (sans la préférence). [] si échec."""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "MX")
        return [str(a.exchange).rstrip(".") for a in answers]
    except Exception:
        return []


def _fetch_snapshot(
    url: str,
    host_header: str | None,
    timeout: int,
) -> dict[str, Any]:
    """
    Récupère un « instantané » comparable d'une URL.

    Si host_header est fourni, la requête vise l'IP (dans url) mais annonce le
    domaine réel via l'en-tête Host — c'est la manœuvre qui révèle une origine
    exposée. La vérification TLS est désactivée pour ce cas précis car le
    certificat de l'IP ne correspondra pas au domaine (attendu, non pertinent
    pour juger de l'exposition).
    """
    headers = dict(DEFAULT_HEADERS)
    verify = True
    if host_header:
        headers["Host"] = host_header
        verify = False

    response = requests.get(
        url,
        headers=headers,
        timeout=timeout,
        allow_redirects=False,
        verify=verify,
    )
    body = response.text or ""
    return {
        "status": response.status_code,
        "title": _extract_title(body),
        "server": response.headers.get("Server"),
        "body_len": len(body),
        "body_snippet": body[:BODY_SNIPPET_LEN],
    }


def verify_origin_exposure(
    candidate_ip: str,
    target_host: str,
    scheme: str = "https",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Étage ACTIF : confirme si `candidate_ip` sert directement l'application de
    `target_host`, contournant Cloudflare.

    ⚠️ Émet du trafic vers l'IP candidate. À n'appeler QUE sur une IP autorisée
    par le RoE (catégorie active_scan). La gouvernance reste à la charge de
    l'appelant (agent Scanning / orchestrateur), pas de cet outil.

    Méthode : on récupère la réponse « normale » via le domaine (fronté par
    Cloudflare), puis la réponse de l'IP directe avec l'en-tête Host = domaine.
    Si les deux servent la même application, l'origine est exposée.

    Returns:
        Dict : status, candidate_ip, target_host, exposed (bool), confidence,
        comparison (signaux), finding (dict prêt pour le rapport) ou None, error.
    """
    started_at = datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "status": "success",
        "candidate_ip": candidate_ip,
        "target_host": target_host,
        "exposed": False,
        "confidence": 0.0,
        "comparison": None,
        "finding": None,
        "error": None,
    }

    try:
        front = _fetch_snapshot(f"{scheme}://{target_host}/", host_header=None, timeout=timeout)
        origin = _fetch_snapshot(
            f"{scheme}://{candidate_ip}/", host_header=target_host, timeout=timeout
        )

        comparison = compare_responses(front, origin)
        result["comparison"] = comparison
        result["confidence"] = comparison["confidence"]
        result["exposed"] = comparison["same_app"]

        if comparison["same_app"]:
            result["finding"] = {
                "type": "exposed_origin_behind_cloudflare",
                "severity": "high",
                "title": "Serveur d'origine exposé derrière Cloudflare",
                "description": (
                    f"L'IP {candidate_ip} sert directement l'application de "
                    f"{target_host}. Un attaquant peut viser cette IP pour "
                    f"contourner entièrement le WAF/anti-DDoS Cloudflare."
                ),
                "evidence": comparison["signals"],
                "owasp": "A05:2021",
                "attack_mapping": "T1590.005",
                "remediation": (
                    "Restreindre l'accès de l'origine aux seules plages IP "
                    "Cloudflare (pare-feu / security group), ou activer "
                    "Cloudflare Authenticated Origin Pulls (mTLS)."
                ),
            }

    except requests.exceptions.RequestException as e:
        result["status"] = "error"
        result["error"] = f"Erreur réseau : {type(e).__name__}: {str(e)}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"

    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    return result
