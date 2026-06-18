"""
Outil de test d'injection de scripts (XSS) pour PENTAGON.

Détecte les Cross-Site Scripting (OWASP A03) par attaque réelle, sur deux
vecteurs génériques :

  1. XSS RÉFLÉCHI : on injecte un marqueur HTML dans un paramètre ; si la
     réponse renvoie ce marqueur NON ÉCHAPPÉ (balise brute, pas d'entités
     HTML), l'application n'encode pas sa sortie → injection de script possible.

  2. XSS STOCKÉ : on enregistre un marqueur HTML via un endpoint d'écriture
     (ex. commentaires), puis on le relit ; s'il revient NON ÉCHAPPÉ, le
     contenu est stocké sans assainissement → XSS stocké.

Détection SANS navigateur : on prouve la condition serveur (réflexion/stockage
sans encodage de sortie), qui est la cause racine du XSS. La preuve d'exécution
côté client relève d'un outil à navigateur (amélioration future).

Conçu pour être GÉNÉRIQUE : aucune donnée spécifique à une cible. Les points
d'injection proviennent de la découverte ; noms de paramètres/champs et marqueur
sont universels.

Catégorie d'action RoE : exploitation (outil offensif).
Standards :
- OWASP A03:2021 (Injection)
- OWASP WSTG-INPV-01/02 (Testing for Reflected/Stored XSS)
- CWE-79 (Cross-site Scripting)
- MITRE ATT&CK T1190

GARDE-FOUS ÉTHIQUES :
- Marqueur NON EXÉCUTABLE : on injecte une fausse balise inerte
  (<pgnxss...>), JAMAIS de <script>alert()> ou de gestionnaire d'événement
  actif. On prouve le point d'injection sans planter de XSS vivant sur la cible
  (essentiel pour le stocké, qui toucherait de vrais utilisateurs).
- Nombre de charges/champs limité, délai entre requêtes.
- L'écriture (XSS stocké) se limite à un marqueur inerte clairement identifiable.
"""

import time
import requests
from datetime import datetime, timezone
from typing import Any


DEFAULT_TIMEOUT = 15
DEFAULT_HEADERS = {"User-Agent": "PENTAGON-Exploitation-Agent/1.0"}

# Marqueur unique et INERTE (fausse balise, n'exécute aucun script). S'il
# revient brut dans la réponse, l'encodage de sortie est absent → XSS possible.
XSS_MARKER = "pgnxss7s9"
XSS_CANARY = f"<{XSS_MARKER}>"                 # forme brute (dangereuse si reflétée)
XSS_CANARY_ESCAPED = f"&lt;{XSS_MARKER}&gt;"   # forme correctement échappée (sûre)

# Noms de paramètres GET courants susceptibles d'être reflétés (génériques).
COMMON_REFLECT_PARAMS = ["q", "search", "query", "keyword", "s", "term", "filter", "name"]

# Noms de champs de contenu courants pour le XSS stocké (génériques).
COMMON_CONTENT_FIELDS = ["content", "text", "comment", "message", "body", "review", "description"]

# Champs typiquement générés par le serveur : on ne les renvoie pas dans un POST
# (ils provoqueraient un rejet ou seraient ignorés).
SERVER_SET_FIELDS = {
    "id", "_id", "uuid", "createdat", "updatedat", "timestamp", "date",
    "userid", "author", "authorid", "ownerid",
}


def run_xss_test(
    reflected_urls: list[str] | None = None,
    stored_collections: list[str] | None = None,
    token: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    delay_between_requests: float = 0.6,
) -> dict[str, Any]:
    """
    Teste le XSS réfléchi (paramètres) et/ou stocké (endpoints d'écriture).

    Args:
        reflected_urls: URLs à tester pour le XSS réfléchi (paramètres GET).
        stored_collections: URLs de collections où tenter un XSS stocké
            (POST d'un marqueur puis relecture).
        token: token d'authentification pour les endpoints protégés.
        timeout: délai d'attente par requête.
        delay_between_requests: délai éthique entre requêtes.

    Returns:
        Dict structuré avec les résultats et les findings XSS.
    """
    started_at = datetime.now(timezone.utc)

    result: dict[str, Any] = {
        "tool": "xss_tester",
        "status": "success",
        "targets_tested": 0,
        "results": [],
        "xss_findings": [],
        "duration_seconds": None,
        "error": None,
    }

    headers = dict(DEFAULT_HEADERS)
    if token and not token.lower().startswith("bearer "):
        headers["Authorization"] = f"Bearer {token}"
    elif token:
        headers["Authorization"] = token

    try:
        # === Vecteur 1 : XSS réfléchi ===
        for url in (reflected_urls or []):
            outcome = _test_reflected(url, headers, timeout, delay_between_requests)
            if outcome is None:
                continue
            result["results"].append(outcome)
            result["targets_tested"] += 1
            result["xss_findings"].extend(outcome.get("findings", []))

        # === Vecteur 2 : XSS stocké ===
        for collection in (stored_collections or []):
            outcome = _test_stored(collection, headers, timeout, delay_between_requests)
            if outcome is None:
                continue
            result["results"].append(outcome)
            result["targets_tested"] += 1
            result["xss_findings"].extend(outcome.get("findings", []))

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"

    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()

    return result


def _test_reflected(
    url: str,
    headers: dict[str, str],
    timeout: int,
    delay: float,
) -> dict[str, Any] | None:
    """
    Injecte le marqueur dans des paramètres GET courants et cherche une
    réflexion NON échappée dans la réponse.
    """
    outcome: dict[str, Any] = {
        "vector": "reflected",
        "target": url,
        "tested_params": 0,
        "findings": [],
    }

    sep = "&" if "?" in url else "?"

    for param in COMMON_REFLECT_PARAMS:
        outcome["tested_params"] += 1
        probe_url = f"{url}{sep}{param}={XSS_CANARY}"
        try:
            response = requests.get(probe_url, headers=headers, timeout=timeout)
        except requests.RequestException:
            time.sleep(delay)
            continue

        body = response.text or ""
        if XSS_CANARY in body and XSS_CANARY_ESCAPED not in body:
            # Marqueur reflété BRUT (non échappé) → injection HTML possible
            ctype = response.headers.get("content-type", "").lower()
            is_html = "html" in ctype
            outcome["findings"].append({
                "title": "XSS réfléchi (réflexion non échappée d'un paramètre)",
                "severity": "high" if is_html else "medium",
                "owasp": "A03:2021 Injection",
                "cwe": "CWE-79",
                "mitre": "T1190",
                "vector": "reflected",
                "target": url,
                "parameter": param,
                "content_type": ctype[:40],
                "evidence": f"Le paramètre '{param}' est reflété sans encodage HTML "
                            f"dans la réponse ({'HTML' if is_html else 'non-HTML, XSS DOM possible côté SPA'}).",
            })
            time.sleep(delay)
            break  # un point d'injection prouvé suffit pour cet URL
        time.sleep(delay)

    return outcome


def _test_stored(
    collection_url: str,
    headers: dict[str, str],
    timeout: int,
    delay: float,
) -> dict[str, Any] | None:
    """
    Tente d'enregistrer le marqueur via POST puis de le relire via GET ;
    cherche un stockage NON échappé.

    Approche SCHEMA-AWARE : on lit d'abord un objet existant de la collection
    pour apprendre son schéma (champs + types), puis on recopie ce schéma valide
    en injectant le marqueur dans le meilleur champ texte. Cela maximise la
    réussite du POST (champs requis fournis) sans deviner. Si la collection est
    vide, on retombe sur des noms de champs de contenu courants.
    """
    outcome: dict[str, Any] = {
        "vector": "stored",
        "target": collection_url,
        "tested_fields": 0,
        "findings": [],
        "notes": [],
    }

    post_headers = dict(headers)
    post_headers["Content-Type"] = "application/json"

    # 1. Apprend le schéma depuis un objet existant
    sample = None
    try:
        getr = requests.get(collection_url, headers=headers, timeout=timeout)
        sample = _extract_sample_object(getr)
    except requests.RequestException:
        pass
    time.sleep(delay)

    # 2. Construit les tentatives de POST
    attempts: list[tuple[dict[str, Any], str]] = []
    if sample:
        body, inject_field = _build_post_from_sample(sample)
        if inject_field:
            outcome["notes"].append(
                f"Schéma appris ({len(sample)} champs) ; injection dans '{inject_field}'."
            )
            attempts.append((body, inject_field))
    if not attempts:
        # Repli : on devine le champ de contenu (collection vide ou non apprise)
        outcome["notes"].append("Schéma non appris ; repli sur des noms de champs courants.")
        for field in COMMON_CONTENT_FIELDS:
            attempts.append(({field: f"PENTAGON test {XSS_CANARY}"}, field))

    # 3. Exécute les tentatives
    for body, field in attempts:
        outcome["tested_fields"] += 1
        try:
            post = requests.post(collection_url, json=body, headers=post_headers, timeout=timeout)
        except requests.RequestException:
            time.sleep(delay)
            continue

        if post.status_code not in (200, 201):
            time.sleep(delay)
            continue

        # Relit la collection pour voir si le marqueur a été stocké
        try:
            getr = requests.get(collection_url, headers=headers, timeout=timeout)
        except requests.RequestException:
            time.sleep(delay)
            continue

        page = getr.text or ""
        if XSS_CANARY in page and XSS_CANARY_ESCAPED not in page:
            outcome["findings"].append({
                "title": "XSS stocké (contenu enregistré sans assainissement)",
                "severity": "high",
                "owasp": "A03:2021 Injection",
                "cwe": "CWE-79",
                "mitre": "T1190",
                "vector": "stored",
                "target": collection_url,
                "field": field,
                "evidence": f"Un marqueur HTML envoyé via le champ '{field}' est "
                            "relu NON échappé dans la collection : le contenu est "
                            "stocké sans encodage → XSS stocké.",
            })
            time.sleep(delay)
            break  # preuve obtenue
        elif XSS_CANARY_ESCAPED in page:
            outcome["notes"].append(f"Champ '{field}' : stocké mais correctement échappé (sûr).")
        time.sleep(delay)

    return outcome


def _extract_sample_object(response: requests.Response) -> dict[str, Any] | None:
    """Extrait un objet représentatif d'une réponse de collection JSON."""
    try:
        data = response.json()
    except ValueError:
        return None
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0]
    if isinstance(data, dict):
        # Cas {"items": [...]} ou {"data": [...]}
        for value in data.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value[0]
        # Sinon, l'objet lui-même s'il a des champs simples
        if data:
            return data
    return None


def _build_post_from_sample(sample: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """
    Construit un corps de POST en recopiant le schéma d'un objet existant,
    en omettant les champs gérés par le serveur, et en choisissant le meilleur
    champ texte où injecter le marqueur.

    Returns:
        (corps_du_post, champ_d_injection ou None)
    """
    body: dict[str, Any] = {}
    string_fields: list[tuple[str, int]] = []

    for key, value in sample.items():
        key_norm = key.lower().replace("_", "")
        if key_norm in SERVER_SET_FIELDS:
            continue
        if isinstance(value, bool):
            body[key] = value
        elif isinstance(value, (int, float)):
            body[key] = value          # réutilise la valeur réelle (ex. productId valide)
        elif isinstance(value, str):
            body[key] = "PENTAGON"
            string_fields.append((key, len(value)))
        # on ignore None / listes / objets imbriqués

    # Choix du champ d'injection : un nom évoquant du contenu, sinon le plus long
    inject_field = None
    for key, _ in string_fields:
        if any(hint in key.lower() for hint in COMMON_CONTENT_FIELDS):
            inject_field = key
            break
    if not inject_field and string_fields:
        inject_field = max(string_fields, key=lambda kv: kv[1])[0]

    if inject_field:
        body[inject_field] = f"PENTAGON test {XSS_CANARY}"

    return body, inject_field
