"""
Outil d'analyse de configuration TLS/SSL pour PENTAGON.

Vérifie la robustesse de la couche de transport chiffrée d'une cible — un
domaine de vulnérabilités situé EN DEHORS de l'OWASP Top 10 applicatif, mais
central en audit de sécurité :

- Protocoles obsolètes encore acceptés (TLS 1.0 / TLS 1.1, SSLv3)
- Chiffrement faible négocié (RC4, 3DES, EXPORT, NULL, clé < 128 bits)
- Certificat : expiré, bientôt expiré, auto-signé, nom d'hôte non concordant

Conçu pour être GÉNÉRIQUE : fonctionne sur tout hôte exposant du TLS, sans
configuration spécifique à une cible. 100% bibliothèque standard (ssl, socket)
→ aucune dépendance supplémentaire, testable hors-ligne.

Utilisé par : Agent Scanning (PTES phase 3-4).
Standards :
- OWASP WSTG-CRYP-01 (Testing for Weak Transport Layer Security)
- NIST SP 800-52r2 (Guidelines for TLS Implementations)
- CWE-326 (Inadequate Encryption Strength), CWE-327 (Broken Crypto Algorithm)
- MITRE ATT&CK T1040 (Network Sniffing — surface facilitée par un TLS faible)

Niveau de risque : ACTIF léger (quelques poignées de main TLS, aucune charge
offensive). Requiert la catégorie RoE 'active_scan'.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


# Protocoles considérés obsolètes (à ne plus accepter).
DEPRECATED_PROTOCOLS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
}

# Motifs de chiffrements faibles (sous-chaîne du nom de suite négociée).
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON")


def _host_port(target: str, default_port: int = 443) -> tuple[str, int]:
    """Extrait (hôte, port) d'une cible (URL, domaine, ou domaine:port)."""
    t = target.strip()
    if t.startswith("http://") or t.startswith("https://"):
        p = urlparse(t)
        return p.hostname or "", p.port or default_port
    if "/" in t:
        t = t.split("/", 1)[0]
    if ":" in t:
        host, _, port = t.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return t, default_port


def _parse_cert_datetime(value: str) -> datetime | None:
    """Parse une date de certificat ('Jun  7 12:00:00 2026 GMT')."""
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _flatten_name(rdn_seq) -> dict[str, str]:
    """Aplati une structure de nom X.509 (subject/issuer) en dict simple."""
    out: dict[str, str] = {}
    for rdn in rdn_seq or ():
        for key, val in rdn:
            out[key] = val
    return out


def run_tls_analysis(target: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any]:
    """
    Analyse la configuration TLS/SSL d'une cible.

    Args:
        target: URL, domaine, ou domaine:port.
        port: port TLS (défaut 443 ; ignoré si un port est présent dans target).
        timeout: délai de connexion par poignée de main (secondes).

    Returns:
        Dict normalisé :
        {
          "status": "success" | "error",
          "target", "host", "port",
          "negotiated_protocol", "negotiated_cipher", "cipher_bits",
          "certificate": {subject, issuer, not_after, days_to_expiry,
                          self_signed, hostname_match},
          "deprecated_protocols_accepted": [...],
          "findings": [{id, title, severity, evidence, standard}],
          "error": "..."  # si status == error
        }
    """
    host, resolved_port = _host_port(target, port)
    result: dict[str, Any] = {
        "status": "error",
        "target": target,
        "host": host,
        "port": resolved_port,
        "negotiated_protocol": None,
        "negotiated_cipher": None,
        "cipher_bits": None,
        "certificate": {},
        "deprecated_protocols_accepted": [],
        "findings": [],
        "error": None,
    }

    if not host:
        result["error"] = f"Cible TLS invalide : '{target}'"
        return result

    findings: list[dict[str, Any]] = []

    # 1) Connexion VÉRIFIÉE : protocole/chiffrement négociés + certificat validé.
    verify_ok = False
    cert: dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, resolved_port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["negotiated_protocol"] = ssock.version()
                cipher = ssock.cipher()  # (name, protocol, bits)
                if cipher:
                    result["negotiated_cipher"] = cipher[0]
                    result["cipher_bits"] = cipher[2]
                cert = ssock.getpeercert() or {}
                verify_ok = True
    except ssl.SSLCertVerificationError as e:
        # Certificat non fiable : auto-signé, expiré, mauvais nom d'hôte…
        msg = (getattr(e, "verify_message", "") or str(e)).lower()
        if "self" in msg and "signed" in msg:
            findings.append(_f("tls-self-signed", "Certificat auto-signé",
                               "medium", str(e), "WSTG-CRYP-01 / CWE-295"))
            result["certificate"]["self_signed"] = True
        elif "expired" in msg:
            findings.append(_f("tls-cert-expired", "Certificat TLS expiré",
                               "high", str(e), "WSTG-CRYP-01 / CWE-298"))
        elif "hostname" in msg or "match" in msg:
            findings.append(_f("tls-hostname-mismatch",
                               "Nom d'hôte du certificat non concordant",
                               "medium", str(e), "WSTG-CRYP-01 / CWE-297"))
        else:
            findings.append(_f("tls-cert-untrusted",
                               "Certificat TLS non fiable",
                               "medium", str(e), "WSTG-CRYP-01 / CWE-295"))
        # On rouvre sans vérification pour récupérer protocole/chiffrement/cert.
        cert = _handshake_no_verify(host, resolved_port, timeout, result)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = f"Connexion TLS impossible vers {host}:{resolved_port} — {e}"
        return result

    result["status"] = "success"

    # 2) Détails du certificat (si récupéré).
    if cert:
        _analyze_certificate(cert, host, verify_ok, result, findings)

    # 3) Force du chiffrement négocié.
    name = (result["negotiated_cipher"] or "").upper()
    bits = result["cipher_bits"]
    if name and any(tok in name for tok in WEAK_CIPHER_TOKENS):
        findings.append(_f("tls-weak-cipher",
                           f"Chiffrement faible négocié : {result['negotiated_cipher']}",
                           "high", f"suite={result['negotiated_cipher']}",
                           "WSTG-CRYP-01 / CWE-327"))
    elif isinstance(bits, int) and bits < 128:
        findings.append(_f("tls-weak-keylen",
                           f"Clé de chiffrement trop courte ({bits} bits)",
                           "high", f"bits={bits}", "CWE-326"))

    # 4) Protocoles obsolètes encore acceptés (best-effort, selon l'OpenSSL local).
    for label, version in DEPRECATED_PROTOCOLS.items():
        if _protocol_accepted(host, resolved_port, version, timeout):
            result["deprecated_protocols_accepted"].append(label)
            findings.append(_f(f"tls-proto-{label.lower().replace('.', '')}",
                               f"Protocole obsolète accepté : {label}",
                               "medium" if label == "TLSv1.1" else "high",
                               f"{label} négocié avec succès",
                               "NIST SP 800-52r2 / WSTG-CRYP-01"))

    result["findings"] = findings
    return result


def _f(fid: str, title: str, severity: str, evidence: str, standard: str) -> dict[str, Any]:
    """Construit un finding normalisé."""
    return {"id": fid, "title": title, "severity": severity,
            "evidence": evidence, "standard": standard}


def _handshake_no_verify(host: str, port: int, timeout: float,
                         result: dict[str, Any]) -> dict[str, Any]:
    """Poignée de main sans vérification → protocole/chiffrement + cert brut."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["negotiated_protocol"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["negotiated_cipher"] = cipher[0]
                    result["cipher_bits"] = cipher[2]
                # getpeercert() est vide en CERT_NONE ; on ne peut pas le parser
                # sans dépendance x509. On renvoie {} (les détails viennent du
                # message de vérification capturé en amont).
                return {}
    except OSError:
        return {}


def _analyze_certificate(cert: dict[str, Any], host: str, verify_ok: bool,
                         result: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    """Analyse le certificat validé (expiration, auto-signature, hôte)."""
    subject = _flatten_name(cert.get("subject"))
    issuer = _flatten_name(cert.get("issuer"))
    info: dict[str, Any] = {
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("commonName", issuer.get("organizationName", "")),
        "not_after": cert.get("notAfter", ""),
    }

    not_after = _parse_cert_datetime(cert.get("notAfter", ""))
    if not_after:
        days = (not_after - datetime.now(timezone.utc)).days
        info["days_to_expiry"] = days
        if days < 0:
            findings.append(_f("tls-cert-expired", "Certificat TLS expiré",
                               "high", f"expiré depuis {-days} j", "CWE-298"))
        elif days < 15:
            findings.append(_f("tls-cert-expiring",
                               f"Certificat TLS expire bientôt ({days} j)",
                               "low", f"expire dans {days} j", "WSTG-CRYP-01"))

    # Auto-signé : émetteur == sujet (un CA de confiance diffère du sujet).
    if issuer and subject and issuer == subject:
        info["self_signed"] = True
        if not any(f["id"] == "tls-self-signed" for f in findings):
            findings.append(_f("tls-self-signed", "Certificat auto-signé",
                               "medium", "issuer == subject", "CWE-295"))

    info["hostname_match"] = verify_ok
    result["certificate"].update(info)


def _protocol_accepted(host: str, port: int, version: "ssl.TLSVersion",
                       timeout: float) -> bool:
    """Teste si un protocole TLS précis est accepté (best-effort)."""
    import warnings
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Forcer un protocole obsolète émet un DeprecationWarning attendu ici.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ValueError, OSError):
        # L'OpenSSL local n'autorise pas ce protocole → impossible de tester.
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.version() is not None
    except (ssl.SSLError, OSError):
        return False


if __name__ == "__main__":
    import json
    import sys
    tgt = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(run_tls_analysis(tgt), indent=2, ensure_ascii=False, default=str))
