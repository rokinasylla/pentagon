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


def run_jwt_analysis(token: str) -> dict[str, Any]:
    """
    Analyse un token JWT pour détecter ses faiblesses.
    
    Args:
        token: le JWT à analyser (format header.payload.signature).
               Générique : provient de n'importe quelle source.
    
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
            cracked = _crack_jwt_secret(token, parts, result["algorithm"])
            if cracked:
                result["cracked_secret"] = cracked
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


def _crack_jwt_secret(token: str, parts: list[str], algorithm: str) -> str | None:
    """
    Tente de retrouver le secret de signature HMAC via un dictionnaire.
    
    Générique : teste une liste universelle de secrets faibles.
    Pour chaque secret candidat, recalcule la signature et compare.
    """
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
    
    # Teste chaque secret du dictionnaire
    for secret in WEAK_JWT_SECRETS:
        computed = hmac.new(secret.encode(), signing_input, hash_func).digest()
        computed_b64 = base64.urlsafe_b64encode(computed).rstrip(b"=").decode()
        
        if computed_b64 == expected_signature:
            return secret
    
    return None


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
