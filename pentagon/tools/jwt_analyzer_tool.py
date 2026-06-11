"""
Outil d'analyse de tokens JWT pour PENTAGON.

Cet outil décode et analyse les JSON Web Tokens (JWT) pour détecter
les faiblesses de configuration : algorithmes non sécurisés, secrets
faibles, absence d'expiration, données sensibles exposées.

Conçu pour être GÉNÉRIQUE : analyse tout JWT au format standard,
sans connaissance spécifique d'une application.

Utilisé par : Agent Web App (PTES phase 4)
Standards :
- OWASP A02:2021 (Cryptographic Failures)
- OWASP A07:2021 (Identification and Authentication Failures)
- CWE-347 (Improper Verification of Cryptographic Signature)
- CWE-321 (Use of Hard-coded Cryptographic Key)
- RFC 7519 (JSON Web Token)

Niveau de risque : PASSIF (décodage et analyse, pas de forge envoyée)
"""

import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any


# Liste de secrets JWT faibles couramment utilisés (universelle)
WEAK_JWT_SECRETS = [
    "secret", "secretkey", "secret_key", "jwt_secret", "jwtsecret",
    "password", "123456", "key", "private", "token", "mysecret",
    "supersecret", "changeme", "default", "test", "admin",
    "your-256-bit-secret", "your_jwt_secret", "secretpassword",
    "qwerty", "letmein", "jwt", "app_secret", "appsecret",
]

# Algorithmes considérés comme faibles ou dangereux
WEAK_ALGORITHMS = {
    "none": "Aucune signature — token forgeable sans secret",
    "HS256": None,  # acceptable SI le secret est fort (on teste le secret)
}


def run_jwt_analysis(
    token: str,
    context_hints: list[str] | None = None,
) -> dict[str, Any]:
    """
    Analyse un token JWT pour détecter ses faiblesses.

    Args:
        token: le JWT à analyser (format header.payload.signature).
               Générique : provient de n'importe quelle source.
        context_hints: indices de contexte (nom d'app, domaine cible...)
               à partir desquels dériver des candidats de secret
               supplémentaires. GÉNÉRIQUE : beaucoup d'applications utilisent
               leur propre nom comme secret de signature. Les indices sont
               fournis par l'agent appelant (depuis la découverte), jamais
               codés en dur dans l'outil.

    Returns:
        Dictionnaire structuré contenant :
        - status: "success" ou "error"
        - is_valid_jwt: si le token a bien un format JWT
        - header: header décodé (algorithme, type)
        - payload: payload décodé (claims)
        - findings: liste des faiblesses détectées
        - cracked_secret: le secret trouvé si crackable
        - summary: statistiques
    """
    started_at = datetime.now(timezone.utc)
    
    result: dict[str, Any] = {
        "status": "success",
        "is_valid_jwt": False,
        "header": None,
        "payload": None,
        "algorithm": None,
        "findings": [],
        "cracked_secret": None,
        "sensitive_claims": [],
        "privilege_claims": [],
        "is_forgeable": False,
        "duration_seconds": None,
        "error": None,
    }
    
    try:
        # Nettoie le token (enlève "Bearer " si présent)
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        
        # Vérifie le format JWT (3 parties séparées par des points)
        parts = token.split(".")
        if len(parts) != 3:
            result["status"] = "error"
            result["error"] = "Format JWT invalide (attendu : header.payload.signature)"
            return result
        
        result["is_valid_jwt"] = True
        
        # Décode le header et le payload
        header = _decode_jwt_part(parts[0])
        payload = _decode_jwt_part(parts[1])
        
        result["header"] = header
        result["payload"] = payload
        result["algorithm"] = header.get("alg", "inconnu") if header else "inconnu"
        
        # === Analyse des faiblesses ===
        
        # 1. Algorithme "none"
        if result["algorithm"].lower() == "none":
            result["is_forgeable"] = True
            result["findings"].append({
                "title": "Algorithme de signature 'none' accepté",
                "severity": "critical",
                "owasp": "A02:2021 Cryptographic Failures",
                "cwe": "CWE-347",
                "description": "Le token utilise l'algorithme 'none', ce qui signifie "
                               "qu'aucune signature n'est vérifiée. Un attaquant peut "
                               "forger n'importe quel token.",
            })

        # 2. Tentative de crack du secret (pour HS256/HS384/HS512)
        if result["algorithm"].upper().startswith("HS"):
            # Liste de secrets candidats : faibles universels + variantes
            # dérivées du contexte (nom d'app/domaine fourni par l'appelant).
            candidates = WEAK_JWT_SECRETS + _derive_secret_candidates(context_hints)
            cracked = _crack_jwt_secret(token, parts, result["algorithm"], candidates)
            if cracked:
                result["cracked_secret"] = cracked
                result["is_forgeable"] = True
                result["findings"].append({
                    "title": f"Secret JWT faible cassé : '{cracked}'",
                    "severity": "critical",
                    "owasp": "A02:2021 / A07:2021",
                    "cwe": "CWE-321",
                    "description": f"Le secret de signature est un mot faible ('{cracked}') "
                                   "trouvé par dictionnaire. Un attaquant peut forger des "
                                   "tokens arbitraires (élévation de privilèges, usurpation).",
                })
        
        # 3. Absence d'expiration
        if payload and "exp" not in payload:
            result["findings"].append({
                "title": "Token sans date d'expiration (claim 'exp' absent)",
                "severity": "medium",
                "owasp": "A07:2021 Authentication Failures",
                "cwe": "CWE-613",
                "description": "Le token n'a pas de date d'expiration. S'il est volé, "
                               "il reste valable indéfiniment.",
            })
        
        # 4. Données sensibles dans le payload
        if payload:
            sensitive = _find_sensitive_claims(payload)
            if sensitive:
                result["sensitive_claims"] = sensitive
                result["findings"].append({
                    "title": "Données sensibles exposées dans le payload JWT",
                    "severity": "medium",
                    "owasp": "A02:2021 Cryptographic Failures",
                    "cwe": "CWE-312",
                    "description": f"Le payload contient des champs sensibles ({', '.join(sensitive)}). "
                                   "Le payload JWT est seulement encodé (base64), pas chiffré : "
                                   "il est lisible par quiconque intercepte le token.",
                })

        # 5bis. Claims de fuite d'information (debug, version, environnement)
        # Ces claims n'ont rien à faire dans un token : ils renseignent
        # l'attaquant sur la pile technique / la version (→ recherche de CVE).
        if payload:
            info_leak = _find_info_leak_claims(payload)
            if info_leak:
                values = ", ".join(f"{k}={v}" for k, v in info_leak.items())
                result["findings"].append({
                    "title": "Fuite d'information dans le payload JWT",
                    "severity": "low",
                    "owasp": "A05:2021 Security Misconfiguration",
                    "cwe": "CWE-200",
                    "description": f"Le payload expose des informations techniques superflues "
                                   f"({values}). Lisibles par quiconque décode le token, elles "
                                   "renseignent un attaquant sur la version/configuration "
                                   "(facilite la recherche de vulnérabilités connues).",
                })

        # 5. Claims de privilège / autorisation exposés (rôle, droits)
        # Distinct des données sensibles : ces claims portent la décision
        # d'autorisation. Lisibles dans le payload (base64, non chiffré), ils
        # renseignent l'attaquant sur la cible à forger. La gravité dépend du
        # CONTEXTE : si le token est forgeable (algo 'none' ou secret cassé),
        # l'attaquant peut réécrire ces claims → élévation de privilèges.
        if payload:
            privilege = _find_privilege_claims(payload)
            if privilege:
                result["privilege_claims"] = privilege
                if result["is_forgeable"]:
                    sev = "critical"
                    impact = ("Comme le token est forgeable (signature non vérifiable), "
                              "un attaquant peut réécrire ces claims pour s'octroyer des "
                              "privilèges (élévation vers un compte administrateur).")
                else:
                    sev = "low"
                    impact = ("Le token n'est pas forgeable avec les secrets testés, mais "
                              "ces claims restent lisibles : ils révèlent le modèle "
                              "d'autorisation et la valeur à viser en cas de forge.")
                values = ", ".join(f"{k}={v}" for k, v in privilege.items())
                result["findings"].append({
                    "title": "Claims de privilège exposés dans le payload JWT",
                    "severity": sev,
                    "owasp": "A07:2021 Identification and Authentication Failures",
                    "cwe": "CWE-639",
                    "description": f"Le payload expose des informations d'autorisation en clair "
                                   f"({values}). {impact}",
                })

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"
    
    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    
    return result


def _decode_jwt_part(part: str) -> dict[str, Any] | None:
    """
    Décode une partie d'un JWT (base64url) en dictionnaire.
    """
    try:
        # Ajoute le padding base64 manquant si nécessaire
        padding = "=" * (-len(part) % 4)
        decoded_bytes = base64.urlsafe_b64decode(part + padding)
        return json.loads(decoded_bytes)
    except Exception:
        return None


def _crack_jwt_secret(
    token: str,
    parts: list[str],
    algorithm: str,
    candidates: list[str] | None = None,
) -> str | None:
    """
    Tente de retrouver le secret de signature HMAC via un dictionnaire.

    Générique : teste une liste de secrets candidats (faibles universels,
    éventuellement enrichis de variantes dérivées du contexte).
    Pour chaque secret candidat, recalcule la signature et compare.
    """
    if candidates is None:
        candidates = WEAK_JWT_SECRETS

    # Détermine la fonction de hash selon l'algorithme
    hash_funcs = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_func = hash_funcs.get(algorithm.upper())
    if not hash_func:
        return None

    # Le message signé est "header.payload"
    signing_input = f"{parts[0]}.{parts[1]}".encode()

    # La signature attendue (3e partie du token)
    expected_signature = parts[2]

    # Teste chaque secret candidat (déduplique en préservant l'ordre)
    seen = set()
    for secret in candidates:
        if secret in seen:
            continue
        seen.add(secret)
        computed = hmac.new(secret.encode(), signing_input, hash_func).digest()
        computed_b64 = base64.urlsafe_b64encode(computed).rstrip(b"=").decode()

        if computed_b64 == expected_signature:
            return secret

    return None


def _derive_secret_candidates(context_hints: list[str] | None) -> list[str]:
    """
    Dérive des candidats de secret à partir d'indices de contexte.

    GÉNÉRIQUE : beaucoup d'applications signent leurs JWT avec un secret
    trivialement lié à leur nom (ex. 'monapp', 'monapp-secret', 'monapp123').
    On génère ces variantes à partir des indices fournis par l'appelant
    (nom d'app, domaine), sans coder en dur aucune cible.
    """
    if not context_hints:
        return []

    # Suffixes/préfixes triviaux couramment accolés à un nom d'app
    affixes = ["", "secret", "_secret", "-secret", "key", "_key",
               "123", "secretkey", "jwt", "_jwt"]

    bases: set[str] = set()
    for hint in context_hints:
        if not hint:
            continue
        token = hint.strip().lower()
        # Extrait le label significatif d'un domaine (ex. 'techshop' depuis
        # 'techshop-vuln.rokina-sylla.me' ou 'techshop-backend-cc1t.onrender.com')
        first_label = token.split(".")[0]
        for piece in (token, first_label, first_label.split("-")[0]):
            piece = piece.strip()
            if len(piece) >= 3:
                bases.add(piece)

    candidates: list[str] = []
    for base in bases:
        for affix in affixes:
            candidates.append(base + affix)
    return candidates


# Claims (champs) sensibles à détecter dans un payload JWT
SENSITIVE_CLAIM_NAMES = [
    "password", "passwd", "pwd", "secret", "credit", "card",
    "ssn", "api_key", "apikey", "private", "token",
]


def _find_sensitive_claims(payload: dict[str, Any]) -> list[str]:
    """
    Détecte les claims sensibles dans le payload d'un JWT.
    """
    found = []
    for key in payload.keys():
        key_lower = key.lower()
        for sensitive in SENSITIVE_CLAIM_NAMES:
            if sensitive in key_lower:
                found.append(key)
                break
    return found


# Claims (champs) portant une information d'autorisation / de privilège.
# Génériques : on retrouve ces noms dans les schémas JWT les plus courants
# (Spring Security, Auth0, Keycloak, etc.).
PRIVILEGE_CLAIM_NAMES = [
    "role", "roles", "authorities", "authority", "scope", "scopes",
    "permissions", "perm", "grp", "groups", "isadmin", "is_admin",
    "admin", "privilege", "privileges", "access_level", "level", "acl",
]


def _find_privilege_claims(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Détecte les claims d'autorisation/privilège dans le payload d'un JWT.

    Retourne un dict {claim: valeur} pour les claims reconnus, afin de
    montrer la valeur exposée (ex. role=ADMIN) — utile à l'agent Web App
    pour juger l'impact (escalade de privilèges si le token est forgeable).
    """
    found: dict[str, Any] = {}
    for key, value in payload.items():
        key_lower = key.lower()
        for name in PRIVILEGE_CLAIM_NAMES:
            if name == key_lower or name in key_lower:
                found[key] = value
                break
    return found


# Claims de fuite d'information : champs techniques qui n'ont pas leur place
# dans un token et renseignent un attaquant (version, environnement, debug).
INFO_LEAK_CLAIM_NAMES = [
    "debug", "debug_info", "version", "ver", "build", "env",
    "environment", "stack", "trace", "hostname", "internal_ip",
]


def _find_info_leak_claims(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Détecte les claims de fuite d'information technique dans le payload.

    Générique : repère les noms de claims évoquant le debug / la version /
    l'environnement, indépendamment de l'application.
    """
    found: dict[str, Any] = {}
    for key, value in payload.items():
        key_lower = key.lower()
        for name in INFO_LEAK_CLAIM_NAMES:
            if name == key_lower or name in key_lower:
                found[key] = value
                break
    return found
