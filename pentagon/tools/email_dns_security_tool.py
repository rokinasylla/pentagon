"""
Outil de sécurité DNS & e-mail pour PENTAGON.

Analyse (en PASSIF, via de simples requêtes DNS publiques) la posture de
sécurité e-mail et DNS d'un domaine — une famille de vulnérabilités EN DEHORS
de l'OWASP Top 10 applicatif, mais à fort impact :

- **SPF** absent ou permissif (`+all`) → un attaquant peut **usurper des
  e-mails** au nom du domaine (phishing crédible).
- **DMARC** absent ou en `p=none` → aucune application : les e-mails usurpés
  passent quand même.
- **DKIM** non détecté (best-effort sur sélecteurs courants) → signature des
  e-mails probablement absente.
- **Transfert de zone AXFR** ouvert → un serveur DNS laisse copier la ZONE
  ENTIÈRE : fuite de toute la cartographie interne (sous-domaines, IP).

100% PASSIF : aucune interaction avec l'application cible, seulement des
requêtes DNS. Catégorie RoE : passive.

Utilisé par : Agent OSINT (PTES phase 2 — Intelligence Gathering).
Standards :
- OWASP WSTG-INFO-04 (Enumerate Infrastructure)
- RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)
- MITRE ATT&CK T1590.002 (Gather Victim Network: DNS), T1598 (Phishing)
- CWE-350 (Reliance on Reverse DNS), CWE-200 (Information Exposure)
"""

from datetime import datetime, timezone
from typing import Any

# NB : dnspython (import dns.*) est importé de façon DIFFÉRÉE dans les fonctions
# qui en ont besoin, afin que ce module s'importe (et que ses helpers purs
# soient testables) même sans dnspython installé.


# Sélecteurs DKIM courants (DKIM est par-sélecteur ; on sonde les plus répandus).
COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "k2", "mail", "dkim", "s1", "s2", "mandrill", "mailjet",
]


def _normalize_domain(target: str) -> str:
    """Extrait le domaine nu d'une URL/cible."""
    t = target.strip().lower()
    for scheme in ("http://", "https://"):
        if t.startswith(scheme):
            t = t[len(scheme):]
    return t.split("/")[0].split(":")[0]


def _txt(resolver, name: str) -> list[str]:
    """Récupère les enregistrements TXT d'un nom (liste de chaînes)."""
    import dns.resolver
    import dns.exception
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.exception.DNSException):
        return []
    out = []
    for rdata in answers:
        try:
            out.append(b"".join(rdata.strings).decode(errors="replace"))
        except Exception:
            out.append(str(rdata))
    return out


def _f(fid: str, title: str, severity: str, evidence: str, standard: str) -> dict[str, Any]:
    return {"id": fid, "title": title, "severity": severity,
            "evidence": evidence, "standard": standard}


def run_email_dns_security(target: str, timeout: float = 8.0) -> dict[str, Any]:
    """
    Analyse la sécurité DNS & e-mail d'un domaine.

    Returns:
        {
          "status": "success" | "error",
          "domain",
          "spf": {"present": bool, "record": str, "policy": str},
          "dmarc": {"present": bool, "record": str, "policy": str},
          "dkim": {"detected_selectors": [...]},
          "axfr": {"vulnerable_nameservers": [...]},
          "findings": [{id, title, severity, evidence, standard}],
          "error": "..."
        }
    """
    domain = _normalize_domain(target)
    result: dict[str, Any] = {
        "status": "success",
        "domain": domain,
        "spf": {"present": False, "record": "", "policy": ""},
        "dmarc": {"present": False, "record": "", "policy": ""},
        "dkim": {"detected_selectors": []},
        "axfr": {"vulnerable_nameservers": []},
        "findings": [],
        "error": None,
    }
    if not domain:
        result["status"] = "error"
        result["error"] = f"Domaine invalide : '{target}'"
        return result

    # Imports différés : la lib DNS n'est requise que pour l'exécution réelle.
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.exception

    findings: list[dict[str, Any]] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    # 1) SPF (TXT v=spf1)
    spf_records = [t for t in _txt(resolver, domain) if t.lower().startswith("v=spf1")]
    if not spf_records:
        findings.append(_f("email-spf-missing", "Enregistrement SPF absent",
                           "medium", "Aucun TXT v=spf1 → usurpation d'e-mail possible",
                           "RFC 7208 / WSTG-INFO-04"))
    else:
        record = spf_records[0]
        result["spf"]["present"] = True
        result["spf"]["record"] = record
        low = record.lower()
        if "+all" in low:
            result["spf"]["policy"] = "+all"
            findings.append(_f("email-spf-permissive",
                               "SPF permissif (+all) — autorise n'importe quel expéditeur",
                               "high", record, "RFC 7208"))
        elif "?all" in low:
            result["spf"]["policy"] = "?all"
            findings.append(_f("email-spf-neutral",
                               "SPF neutre (?all) — n'empêche pas l'usurpation",
                               "low", record, "RFC 7208"))
        else:
            result["spf"]["policy"] = "-all" if "-all" in low else ("~all" if "~all" in low else "?")

    # 2) DMARC (TXT sur _dmarc.domaine)
    dmarc_records = [t for t in _txt(resolver, f"_dmarc.{domain}")
                     if "v=dmarc1" in t.lower()]
    if not dmarc_records:
        findings.append(_f("email-dmarc-missing", "Enregistrement DMARC absent",
                           "medium", "Aucun TXT v=DMARC1 → pas de protection anti-usurpation",
                           "RFC 7489 / WSTG-INFO-04"))
    else:
        record = dmarc_records[0]
        result["dmarc"]["present"] = True
        result["dmarc"]["record"] = record
        policy = ""
        for part in record.split(";"):
            part = part.strip().lower()
            if part.startswith("p="):
                policy = part[2:].strip()
        result["dmarc"]["policy"] = policy
        if policy == "none":
            findings.append(_f("email-dmarc-none",
                               "DMARC en p=none — aucune application (surveillance seule)",
                               "medium", record, "RFC 7489"))

    # 3) DKIM (best-effort : sélecteurs courants)
    for sel in COMMON_DKIM_SELECTORS:
        txts = _txt(resolver, f"{sel}._domainkey.{domain}")
        if any("v=dkim1" in t.lower() or "p=" in t.lower() for t in txts):
            result["dkim"]["detected_selectors"].append(sel)
    if not result["dkim"]["detected_selectors"]:
        findings.append(_f("email-dkim-not-detected",
                           "DKIM non détecté (sélecteurs courants testés)",
                           "low",
                           "Aucun sélecteur DKIM courant trouvé (best-effort ; "
                           "un sélecteur personnalisé peut exister)",
                           "RFC 6376"))

    # 4) Transfert de zone AXFR (fuite de la zone entière)
    try:
        ns_answers = resolver.resolve(domain, "NS")
        nameservers = [str(r.target).rstrip(".") for r in ns_answers]
    except dns.exception.DNSException:
        nameservers = []

    for ns in nameservers:
        try:
            ns_ip = str(resolver.resolve(ns, "A")[0])
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout))
            if zone is not None:
                result["axfr"]["vulnerable_nameservers"].append(ns)
        except Exception:
            # Le serveur refuse l'AXFR (comportement normal/attendu).
            continue

    if result["axfr"]["vulnerable_nameservers"]:
        findings.append(_f("dns-axfr-open",
                           "Transfert de zone DNS (AXFR) autorisé",
                           "high",
                           "Serveur(s) acceptant l'AXFR : "
                           + ", ".join(result["axfr"]["vulnerable_nameservers"]),
                           "WSTG-INFO-04 / CWE-200"))

    result["findings"] = findings
    return result


if __name__ == "__main__":
    import json
    import sys
    tgt = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(run_email_dns_security(tgt), indent=2, ensure_ascii=False, default=str))
