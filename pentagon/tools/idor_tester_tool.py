"""
Outil de test IDOR / BOLA pour PENTAGON.

IDOR (Insecure Direct Object Reference) / BOLA (Broken Object Level
Authorization) : une faille d'autorisation où un utilisateur authentifié
accède aux ressources d'AUTRES utilisateurs en manipulant un identifiant
d'objet dans l'URL (ex. /api/orders/1, /api/orders/2, ...).

Méthode (boîte noire, offensive) :
  1. On part d'endpoints paramétrés par un identifiant (découverts).
  2. Avec NOTRE token (un seul compte), on énumère quelques identifiants.
  3. Si l'on accède à plusieurs objets DISTINCTS appartenant à des
     utilisateurs différents → accès horizontal non autorisé = IDOR prouvé.

Conçu pour être GÉNÉRIQUE : aucun endpoint ni identifiant spécifique à une
cible. Les endpoints proviennent de la découverte ; les identifiants testés
sont une petite plage universelle.

Catégorie d'action RoE : exploitation (outil offensif).
Standards :
- OWASP A01:2021 (Broken Access Control)
- OWASP API Security Top 10 — API1:2023 (Broken Object Level Authorization)
- OWASP WSTG-ATHZ-04 (Insecure Direct Object References)
- CWE-639 (Authorization Bypass Through User-Controlled Key)
- MITRE ATT&CK T1190

GARDE-FOUS ÉTHIQUES :
- Plage d'identifiants volontairement courte (énumération de preuve, PAS
  d'aspiration massive de données).
- Requêtes en LECTURE SEULE (GET) : on prouve l'accès, on ne modifie rien.
- Délai entre les requêtes pour ne pas surcharger la cible.
- Les valeurs sensibles ne sont PAS conservées : on ne garde que les NOMS
  de champs (preuve de l'exposition sans copier la donnée d'autrui).
"""

import re
import time
import requests
from datetime import datetime, timezone
from typing import Any


DEFAULT_TIMEOUT = 20
DEFAULT_HEADERS = {"User-Agent": "PENTAGON-Exploitation-Agent/1.0"}

# Champs indiquant qu'un objet est lié à un UTILISATEUR (et non un catalogue
# public). Leur présence distingue un vrai IDOR d'un faux positif (ex. /products).
USER_BOUND_FIELD_NAMES = [
    "email", "username", "user", "userid", "owner", "phone", "address",
    "firstname", "lastname", "fullname", "name", "dob", "birthdate",
    "order", "invoice", "account", "customer", "card", "creditcard",
    "ssn", "password", "passwd", "hash", "token", "reset",
]

# Plage d'identifiants par défaut (preuve, pas aspiration massive).
DEFAULT_ID_VALUES = [1, 2, 3, 4, 5]


def run_idor_test(
    base_url: str,
    endpoints: list[str],
    token: str | None = None,
    token_header: str = "Authorization",
    id_values: list | None = None,
    delay_between_requests: float = 0.5,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Teste des endpoints paramétrés par identifiant pour détecter des IDOR.

    Args:
        base_url: URL de base de l'API (ex. "https://backend.com/api").
        endpoints: chemins découverts, possiblement paramétrés
                   (ex. "/orders/{id}", "/users/{param}", "/orders/1").
        token: token d'authentification à présenter (notre compte). Si None,
               le test se fait sans authentification (détecte aussi l'accès
               public, qui est une faille distincte).
        token_header: en-tête où placer le token (défaut Authorization Bearer).
        id_values: identifiants à énumérer (défaut [1..5]).
        delay_between_requests: délai éthique entre requêtes.
        timeout: délai d'attente par requête.

    Returns:
        Dict structuré avec les résultats et les findings IDOR.
    """
    started_at = datetime.now(timezone.utc)
    id_values = id_values if id_values is not None else DEFAULT_ID_VALUES

    result: dict[str, Any] = {
        "tool": "idor_tester",
        "status": "success",
        "base_url": base_url,
        "authenticated": bool(token),
        "id_values_tested": id_values,
        "endpoints_tested": 0,
        "results": [],
        "idor_findings": [],
        "duration_seconds": None,
        "error": None,
    }

    headers = dict(DEFAULT_HEADERS)
    if token:
        # Forme "Bearer <token>" pour l'en-tête Authorization, brut sinon.
        if token_header.lower() == "authorization" and not token.lower().startswith("bearer "):
            headers[token_header] = f"Bearer {token}"
        else:
            headers[token_header] = token

    try:
        for endpoint in endpoints:
            template = _to_id_template(endpoint)
            if not template:
                # Endpoint sans identifiant manipulable → non concerné par l'IDOR
                continue

            endpoint_result = _probe_object_endpoint(
                base_url, template, headers, id_values, delay_between_requests, timeout
            )
            result["results"].append(endpoint_result)
            result["endpoints_tested"] += 1

            finding = _evaluate_idor(endpoint_result, bool(token))
            if finding:
                result["idor_findings"].append(finding)

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"

    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()

    return result


def _to_id_template(endpoint: str) -> str | None:
    """
    Transforme un endpoint en gabarit avec un emplacement d'identifiant {id}.

    Reconnaît, de façon générique :
      - les placeholders : /users/{id}, /users/{param}, /users/:id
      - un segment numérique : /orders/1  →  /orders/{id}
    Retourne None si l'endpoint ne porte aucun identifiant manipulable
    (ex. /products = liste, sans objet ciblé).
    """
    # 1. Placeholder entre accolades : {id}, {param}, {userId}...
    if re.search(r"\{[^}]+\}", endpoint):
        return re.sub(r"\{[^}]+\}", "{id}", endpoint, count=1)

    # 2. Placeholder Express/Spring : :id
    if re.search(r":[A-Za-z_]\w*", endpoint):
        return re.sub(r":[A-Za-z_]\w*", "{id}", endpoint, count=1)

    # 3. Segment purement numérique (ex. /orders/42)
    segments = endpoint.split("/")
    for i, seg in enumerate(segments):
        if seg.isdigit():
            segments[i] = "{id}"
            return "/".join(segments)

    return None


def _probe_object_endpoint(
    base_url: str,
    template: str,
    headers: dict[str, str],
    id_values: list,
    delay: float,
    timeout: int,
) -> dict[str, Any]:
    """
    Énumère les identifiants d'un endpoint paramétré et collecte les réponses.
    """
    endpoint_result: dict[str, Any] = {
        "endpoint_template": template,
        "probes": [],            # une entrée par identifiant testé
        "accessible_ids": [],    # ids renvoyant 200 + objet JSON
        "distinct_objects": 0,   # nombre d'objets distincts atteints
        "user_bound_fields": [], # champs liés à un utilisateur observés
        "error": None,
    }

    object_fingerprints: set = set()

    for id_value in id_values:
        path = template.replace("{id}", str(id_value))
        url = path if path.startswith("http") else base_url.rstrip("/") + "/" + path.lstrip("/")

        probe = {"id": id_value, "url": url, "status_code": None, "returns_json": False}
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            probe["status_code"] = response.status_code
            content_type = response.headers.get("content-type", "").lower()

            if response.status_code == 200 and "json" in content_type:
                try:
                    data = response.json()
                except ValueError:
                    data = None

                if isinstance(data, dict) and data:
                    probe["returns_json"] = True
                    endpoint_result["accessible_ids"].append(id_value)

                    # Empreinte d'objet : valeur d'un champ d'identité s'il existe,
                    # sinon signature des clés — pour compter les objets DISTINCTS.
                    fp = _object_fingerprint(data)
                    object_fingerprints.add(fp)

                    # Champs liés à un utilisateur (preuve que l'objet est privé)
                    for field in _find_user_bound_fields(data):
                        if field not in endpoint_result["user_bound_fields"]:
                            endpoint_result["user_bound_fields"].append(field)
        except requests.exceptions.Timeout:
            probe["error"] = "Timeout"
        except requests.exceptions.RequestException as e:
            probe["error"] = type(e).__name__

        endpoint_result["probes"].append(probe)
        time.sleep(delay)

    endpoint_result["distinct_objects"] = len(object_fingerprints)
    return endpoint_result


def _evaluate_idor(endpoint_result: dict[str, Any], authenticated: bool) -> dict[str, Any] | None:
    """
    Juge si l'énumération constitue une preuve d'IDOR.

    Règle : accéder à >= 2 objets DISTINCTS via le même compte (ou sans auth)
    sur un endpoint d'objet utilisateur = accès horizontal non autorisé.
    La présence de champs liés à un utilisateur écarte le faux positif d'un
    catalogue public.
    """
    distinct = endpoint_result["distinct_objects"]
    user_bound = endpoint_result["user_bound_fields"]
    accessible = endpoint_result["accessible_ids"]

    if distinct < 2:
        return None  # pas de preuve d'accès horizontal multiple

    template = endpoint_result["endpoint_template"]

    if user_bound:
        # Objets liés à des utilisateurs → IDOR confirmé
        severity = "high"
        if not authenticated:
            severity = "critical"  # accessible même sans authentification
        description = (
            f"Accès à {distinct} objet(s) distinct(s) via le seul endpoint "
            f"'{template}' en énumérant l'identifiant"
            + (" SANS authentification" if not authenticated else " avec un compte unique")
            + f". Les objets contiennent des champs liés à l'utilisateur "
              f"({', '.join(user_bound)}), ce qui prouve un accès non autorisé "
              "aux ressources d'autres utilisateurs."
        )
    else:
        # Plusieurs objets atteints mais sans marqueur d'appartenance utilisateur :
        # probablement une ressource publique (catalogue). Candidat à confirmer.
        severity = "low"
        description = (
            f"L'endpoint '{template}' renvoie {distinct} objet(s) distinct(s) par "
            "énumération d'identifiant, mais sans champ manifestement lié à un "
            "utilisateur. Possible ressource publique (faux positif probable) — "
            "à confirmer par jugement contextuel."
        )

    return {
        "title": "Référence directe à un objet non sécurisée (IDOR)",
        "severity": severity,
        "owasp": "A01:2021 Broken Access Control",
        "api_owasp": "API1:2023 Broken Object Level Authorization",
        "cwe": "CWE-639",
        "mitre": "T1190",
        "endpoint_template": template,
        "accessible_ids": accessible,
        "distinct_objects": distinct,
        "user_bound_fields": user_bound,
        "authenticated": authenticated,
        "description": description,
    }


def _object_fingerprint(data: dict[str, Any]) -> str:
    """
    Calcule une empreinte d'objet pour distinguer des ressources différentes.

    Privilégie un champ d'identité ('id', 'uuid'...) ; à défaut, la signature
    des clés. On NE conserve PAS les valeurs sensibles.
    """
    for id_field in ("id", "uuid", "_id", "orderId", "userId", "number"):
        if id_field in data:
            return f"{id_field}={data[id_field]}"
    return "keys:" + ",".join(sorted(data.keys()))


def _find_user_bound_fields(data: Any, found: set | None = None) -> list[str]:
    """
    Détecte récursivement les champs indiquant un objet lié à un utilisateur.
    Générique : ne dépend d'aucune application.
    """
    if found is None:
        found = set()

    if isinstance(data, dict):
        for key, value in data.items():
            key_norm = key.lower().replace("_", "").replace("-", "")
            for marker in USER_BOUND_FIELD_NAMES:
                if marker.replace("_", "") in key_norm:
                    found.add(key)
                    break
            _find_user_bound_fields(value, found)
    elif isinstance(data, list):
        if data:
            _find_user_bound_fields(data[0], found)

    return sorted(found)
