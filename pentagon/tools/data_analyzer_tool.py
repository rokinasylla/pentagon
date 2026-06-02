"""
Outil d'analyse de données sensibles pour PENTAGON.

Cet outil analyse en profondeur des données (réponses JSON) pour détecter :
- Les hashes de mots de passe et leur robustesse (MD5, SHA1, bcrypt...)
- Les mots de passe faibles (via dictionnaire de hashes connus)
- Les numéros de carte bancaire (validation Luhn)
- D'autres données sensibles (tokens, clés, etc.)

Conçu pour être GÉNÉRIQUE : analyse n'importe quelle structure de données
sans connaissance spécifique d'une application.

Utilisé par : Agent Web App (PTES phase 4)
Standards :
- OWASP A02:2021 (Cryptographic Failures)
- CWE-327 (Use of a Broken Cryptographic Algorithm)
- CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- CWE-311 (Missing Encryption of Sensitive Data)

Niveau de risque : PASSIF (analyse de données déjà collectées)
"""

import hashlib
import re
from datetime import datetime, timezone
from typing import Any


# Caractéristiques des algorithmes de hash par longueur (en hexadécimal)
HASH_SIGNATURES = {
    32: {"algo": "MD5", "strength": "weak", "cwe": "CWE-327"},
    40: {"algo": "SHA-1", "strength": "weak", "cwe": "CWE-327"},
    64: {"algo": "SHA-256", "strength": "acceptable", "cwe": None},
    128: {"algo": "SHA-512", "strength": "strong", "cwe": None},
}

# Préfixes de hash modernes (robustes) reconnaissables par leur format
STRONG_HASH_PREFIXES = {
    "$2a$": "bcrypt", "$2b$": "bcrypt", "$2y$": "bcrypt",
    "$argon2": "Argon2", "$scrypt": "scrypt", "$pbkdf2": "PBKDF2",
}

# Dictionnaire de mots de passe faibles courants
# (liste réduite — en production, on chargerait rockyou.txt)
COMMON_PASSWORDS = [
    "password", "123456", "123456789", "12345678", "12345",
    "qwerty", "abc123", "password1", "admin", "admin123",
    "letmein", "welcome", "monkey", "1234567890", "root",
    "toor", "pass", "test", "guest", "111111", "azerty",
    "motdepasse", "soleil", "000000", "user", "changeme",
]


def run_data_analysis(data: Any) -> dict[str, Any]:
    """
    Analyse une structure de données pour détecter des problèmes cryptographiques
    et des expositions de données sensibles.
    
    Args:
        data: structure de données à analyser (dict, list, ou réponse JSON).
              Générique : peut provenir de n'importe quelle API.
    
    Returns:
        Dictionnaire structuré contenant :
        - status: "success" ou "error"
        - findings: liste des problèmes détectés
        - weak_hashes: hashes faibles identifiés (MD5/SHA1)
        - cracked_passwords: mots de passe cassés via dictionnaire
        - exposed_cards: numéros de carte détectés (validés Luhn)
        - summary: statistiques
    """
    started_at = datetime.now(timezone.utc)
    
    result: dict[str, Any] = {
        "status": "success",
        "findings": [],
        "weak_hashes": [],
        "cracked_passwords": [],
        "exposed_cards": [],
        "summary": {
            "weak_hash_count": 0,
            "cracked_password_count": 0,
            "exposed_card_count": 0,
        },
        "duration_seconds": None,
        "error": None,
    }
    
    # Pré-calcule les hashes MD5/SHA1 des mots de passe courants (pour comparaison)
    weak_password_lookup = _build_password_lookup()
    
    try:
        # Parcourt récursivement la structure de données
        _analyze_recursive(data, result, weak_password_lookup)
        
        # Construit les findings synthétiques
        _build_findings(result)
        
        # Statistiques
        result["summary"] = {
            "weak_hash_count": len(result["weak_hashes"]),
            "cracked_password_count": len(result["cracked_passwords"]),
            "exposed_card_count": len(result["exposed_cards"]),
        }
    
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"
    
    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    
    return result


def _build_password_lookup() -> dict[str, str]:
    """
    Pré-calcule les hashes MD5 et SHA1 des mots de passe courants.
    
    Retourne un dict {hash: mot_de_passe_en_clair} pour identification rapide.
    Générique : basé sur un dictionnaire universel, pas sur une cible.
    """
    lookup = {}
    for pwd in COMMON_PASSWORDS:
        md5 = hashlib.md5(pwd.encode()).hexdigest()
        sha1 = hashlib.sha1(pwd.encode()).hexdigest()
        lookup[md5] = pwd
        lookup[sha1] = pwd
    return lookup


def _analyze_recursive(
    data: Any,
    result: dict[str, Any],
    password_lookup: dict[str, str],
    path: str = "",
) -> None:
    """
    Parcourt récursivement une structure de données pour analyser chaque valeur.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            # Si la valeur est une chaîne, on l'analyse
            if isinstance(value, str):
                _analyze_string_value(key, value, current_path, result, password_lookup)
            else:
                # Récursion sur les structures imbriquées
                _analyze_recursive(value, result, password_lookup, current_path)
    
    elif isinstance(data, list):
        for i, item in enumerate(data):
            current_path = f"{path}[{i}]"
            _analyze_recursive(item, result, password_lookup, current_path)


def _analyze_string_value(
    field_name: str,
    value: str,
    path: str,
    result: dict[str, Any],
    password_lookup: dict[str, str],
) -> None:
    """
    Analyse une valeur de type chaîne pour détecter hashes, cartes, etc.
    """
    value = value.strip()
    
    # 1. Détection de hash
    hash_info = _identify_hash(value)
    if hash_info:
        entry = {
            "field": field_name,
            "path": path,
            "algorithm": hash_info["algo"],
            "strength": hash_info["strength"],
            "cwe": hash_info["cwe"],
        }
        
        # Si le hash est faible, on le signale
        if hash_info["strength"] == "weak":
            result["weak_hashes"].append(entry)
            
            # Tente de "casser" le hash via le dictionnaire
            cracked = password_lookup.get(value.lower())
            if cracked:
                result["cracked_passwords"].append({
                    "field": field_name,
                    "path": path,
                    "hash": value[:8] + "...",  # ne montre qu'un fragment
                    "algorithm": hash_info["algo"],
                    "plaintext": cracked,
                })
    
    # 2. Détection de numéro de carte bancaire
    card_info = _identify_credit_card(value)
    if card_info:
        result["exposed_cards"].append({
            "field": field_name,
            "path": path,
            "card_type": card_info["type"],
            "masked": card_info["masked"],
        })


def _identify_hash(value: str) -> dict[str, Any] | None:
    """
    Identifie si une chaîne est un hash et détermine son algorithme.
    
    Générique : basé sur le format (longueur, caractères), pas sur des valeurs connues.
    """
    # Vérifie les préfixes de hash modernes (bcrypt, argon2...)
    for prefix, algo in STRONG_HASH_PREFIXES.items():
        if value.startswith(prefix):
            return {"algo": algo, "strength": "strong", "cwe": None}
    
    # Vérifie les hashes hexadécimaux (MD5, SHA1, SHA256...)
    if re.fullmatch(r"[a-fA-F0-9]+", value):
        length = len(value)
        if length in HASH_SIGNATURES:
            return HASH_SIGNATURES[length]
    
    return None


def _identify_credit_card(value: str) -> dict[str, Any] | None:
    """
    Détecte un numéro de carte bancaire valide via l'algorithme de Luhn.
    
    Générique : détecte tout numéro valide, quel que soit le titulaire.
    """
    # Nettoie le numéro (enlève espaces et tirets)
    digits = re.sub(r"[\s-]", "", value)
    
    # Un numéro de carte fait 13 à 19 chiffres
    if not re.fullmatch(r"\d{13,19}", digits):
        return None
    
    # Validation Luhn
    if not _luhn_check(digits):
        return None
    
    # Détermine le type par préfixe
    card_type = "Inconnu"
    if digits.startswith("4"):
        card_type = "Visa"
    elif digits[:2] in ("51", "52", "53", "54", "55"):
        card_type = "Mastercard"
    elif digits[:2] in ("34", "37"):
        card_type = "American Express"
    
    # Masque le numéro (ne garde que les 4 derniers)
    masked = "*" * (len(digits) - 4) + digits[-4:]
    
    return {"type": card_type, "masked": masked}


def _luhn_check(card_number: str) -> bool:
    """
    Vérifie la validité d'un numéro de carte via l'algorithme de Luhn.
    Standard universel utilisé par toutes les cartes bancaires.
    """
    digits = [int(d) for d in card_number]
    checksum = 0
    # Parcourt de droite à gauche
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _build_findings(result: dict[str, Any]) -> None:
    """Construit les findings synthétiques à partir des détections."""
    
    if result["weak_hashes"]:
        algos = set(h["algorithm"] for h in result["weak_hashes"])
        result["findings"].append({
            "title": f"Utilisation d'algorithmes de hash faibles ({', '.join(algos)})",
            "severity": "high",
            "owasp": "A02:2021 Cryptographic Failures",
            "cwe": "CWE-327",
            "count": len(result["weak_hashes"]),
            "description": "Des mots de passe sont hachés avec des algorithmes "
                           "cryptographiquement faibles, vulnérables aux attaques par "
                           "dictionnaire et rainbow tables.",
        })
    
    if result["cracked_passwords"]:
        result["findings"].append({
            "title": "Mots de passe faibles cassés via dictionnaire",
            "severity": "critical",
            "owasp": "A02:2021 / A07:2021",
            "cwe": "CWE-916",
            "count": len(result["cracked_passwords"]),
            "description": f"{len(result['cracked_passwords'])} mot(s) de passe "
                           "ont été retrouvés en clair à partir de leur hash, "
                           "démontrant l'usage de mots de passe triviaux et de "
                           "hash non salés.",
        })
    
    if result["exposed_cards"]:
        result["findings"].append({
            "title": "Numéros de carte bancaire exposés",
            "severity": "critical",
            "owasp": "A02:2021 Cryptographic Failures",
            "cwe": "CWE-311",
            "count": len(result["exposed_cards"]),
            "description": f"{len(result['exposed_cards'])} numéro(s) de carte "
                           "bancaire valide(s) (vérifiés par Luhn) exposé(s) en clair. "
                           "Violation directe de PCI DSS.",
        })
