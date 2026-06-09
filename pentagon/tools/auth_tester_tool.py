"""
Auth Tester Tool pour PENTAGON.

Outil ACTIF de test d'authentification. Il vérifie la présence
d'identifiants faibles ou par défaut sur un endpoint d'authentification,
et récupère le token d'authentification en cas de succès.

Ce token pourra ensuite être réutilisé par d'autres outils
(jwt_analyzer, idor_tester) pour des tests authentifiés.

GÉNÉRIQUE : aucune donnée spécifique à une cible. La liste d'identifiants
testés est une liste de credentials par défaut universellement connus.

Catégorie d'action RoE : exploitation (outil offensif).
Standards : OWASP A07 (Identification and Authentication Failures),
            WSTG-ATHN (Authentication Testing).

GARDE-FOUS ÉTHIQUES :
- Nombre de tentatives strictement limité (détection de comptes par
  défaut, PAS de brute-force).
- Délai entre les tentatives pour ne pas surcharger la cible.
"""

import time
import requests
from typing import Any


# Liste GÉNÉRIQUE d'identifiants par défaut/faibles universellement connus.
# Ce ne sont PAS des identifiants spécifiques à une cible : ce sont des
# combinaisons par défaut que l'on retrouve dans d'innombrables systèmes.
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("demo", "demo"),
]

# Noms de champs couramment utilisés dans les formulaires de login.
# Permet à l'outil de s'adapter à différentes APIs sans configuration.
COMMON_USERNAME_FIELDS = ["username", "user", "email", "login", "userName"]
COMMON_PASSWORD_FIELDS = ["password", "pass", "pwd", "passwd"]

# Clés où l'on cherche un token dans la réponse JSON.
COMMON_TOKEN_KEYS = ["token", "access_token", "accessToken", "jwt", "auth_token", "id_token"]


class AuthTesterTool:
    """
    Teste la robustesse de l'authentification d'une cible.

    Détecte les identifiants par défaut et récupère un token utilisable
    pour des tests ultérieurs.
    """

    def __init__(self, delay_between_attempts: float = 1.0, timeout: int = 15):
        """
        Args:
            delay_between_attempts: délai (secondes) entre deux tentatives,
                                    pour ne pas surcharger la cible.
            timeout: délai d'attente max par requête.
        """
        self.delay = delay_between_attempts
        self.timeout = timeout
        self.name = "auth_tester"

    def run(
        self,
        login_url: str,
        credentials: list[tuple[str, str]] | None = None,
        username_field: str | None = None,
        password_field: str | None = None,
    ) -> dict[str, Any]:
        """
        Teste l'authentification sur l'endpoint fourni.

        Args:
            login_url: URL complète de l'endpoint de login.
            credentials: liste de paires (username, password) à tester.
                         Si None, utilise la liste générique par défaut.
            username_field: nom du champ username (si connu). Si None,
                            l'outil essaie les noms courants.
            password_field: nom du champ password (si connu). Si None,
                            l'outil essaie les noms courants.

        Returns:
            Dict structuré avec les résultats du test.
        """
        creds_to_test = credentials if credentials is not None else DEFAULT_CREDENTIALS

        result = {
            "tool": self.name,
            "login_url": login_url,
            "tested_count": 0,
            "weak_credentials_found": [],
            "token": None,
            "token_location": None,
            "username_response_disclosure": False,
            "notes": [],
            "error": None,
        }

        # Détermine les champs à utiliser
        user_fields = [username_field] if username_field else COMMON_USERNAME_FIELDS
        pass_fields = [password_field] if password_field else COMMON_PASSWORD_FIELDS

        # On détecte d'abord le bon format de champ avec une requête sonde
        detected_user_field, detected_pass_field = self._detect_field_names(
            login_url, user_fields, pass_fields
        )

        if detected_user_field:
            result["notes"].append(
                f"Champs détectés : '{detected_user_field}' / '{detected_pass_field}'"
            )
        else:
            # Par défaut, on tente le premier de chaque
            detected_user_field = user_fields[0]
            detected_pass_field = pass_fields[0]
            result["notes"].append(
                f"Champs non confirmés, utilisation par défaut : "
                f"'{detected_user_field}' / '{detected_pass_field}'"
            )

        # Teste chaque paire d'identifiants
        for username, password in creds_to_test:
            result["tested_count"] += 1

            try:
                response = requests.post(
                    login_url,
                    json={
                        detected_user_field: username,
                        detected_pass_field: password,
                    },
                    timeout=self.timeout,
                )
            except requests.RequestException as e:
                result["notes"].append(f"Erreur réseau pour {username}: {e}")
                time.sleep(self.delay)
                continue

            # Analyse la réponse pour détecter un succès
            if self._is_successful_login(response):
                token, location = self._extract_token(response)
                result["weak_credentials_found"].append({
                    "username": username,
                    "password": password,
                    "status_code": response.status_code,
                })
                # On garde le premier token trouvé
                if token and not result["token"]:
                    result["token"] = token
                    result["token_location"] = location
                    result["notes"].append(
                        f"Token récupéré via '{username}' (emplacement : {location})"
                    )

            # Délai éthique entre les tentatives
            time.sleep(self.delay)

        # Synthèse
        if result["weak_credentials_found"]:
            result["notes"].append(
                f"⚠ {len(result['weak_credentials_found'])} identifiant(s) "
                f"faible(s) détecté(s)."
            )
        else:
            result["notes"].append("Aucun identifiant par défaut détecté.")

        return result

    def _detect_field_names(
        self, login_url: str, user_fields: list[str], pass_fields: list[str]
    ) -> tuple[str | None, str | None]:
        """
        Tente de détecter les noms de champs attendus par l'API.

        Stratégie simple : on envoie une requête avec des identifiants
        bidons en utilisant le premier format, et on regarde si la réponse
        suggère un format particulier. Pour une v1, on retourne simplement
        les premiers candidats (la détection fine est une amélioration future).
        """
        # v1 : détection minimale. On retourne None pour laisser run()
        # utiliser les valeurs par défaut. (Amélioration future : analyser
        # un message d'erreur type "champ X requis".)
        return None, None

    def _is_successful_login(self, response: requests.Response) -> bool:
        """
        Détermine si une réponse correspond à une connexion réussie.

        Heuristiques :
        - Code 200 ou 201
        - ET présence d'un token dans la réponse, OU absence de message d'échec.
        """
        if response.status_code not in (200, 201):
            return False

        # Cherche un token dans la réponse JSON
        try:
            data = response.json()
            if isinstance(data, dict):
                for key in COMMON_TOKEN_KEYS:
                    if key in data and data[key]:
                        return True
                # Pas de token mais réponse positive sans message d'erreur
                body_text = str(data).lower()
                failure_words = ["invalid", "incorrect", "failed", "error", "unauthorized", "wrong"]
                if not any(word in body_text for word in failure_words):
                    return True
        except ValueError:
            # Réponse non-JSON : on se fie au code + absence de mot d'échec
            body_text = response.text.lower()
            failure_words = ["invalid", "incorrect", "failed", "error", "unauthorized", "wrong"]
            if not any(word in body_text for word in failure_words):
                return True

        return False

    def _extract_token(self, response: requests.Response) -> tuple[str | None, str | None]:
        """
        Extrait un token d'authentification de la réponse.

        Cherche dans : le corps JSON, puis les cookies, puis les headers.

        Returns:
            (token, emplacement) ou (None, None).
        """
        # 1. Dans le corps JSON
        try:
            data = response.json()
            if isinstance(data, dict):
                for key in COMMON_TOKEN_KEYS:
                    if key in data and data[key]:
                        return str(data[key]), f"body.{key}"
                # Parfois le token est imbriqué dans un sous-objet
                for outer_key, outer_val in data.items():
                    if isinstance(outer_val, dict):
                        for key in COMMON_TOKEN_KEYS:
                            if key in outer_val and outer_val[key]:
                                return str(outer_val[key]), f"body.{outer_key}.{key}"
        except ValueError:
            pass

        # 2. Dans les cookies
        for cookie_name in response.cookies.keys():
            if any(tk in cookie_name.lower() for tk in ["token", "session", "auth", "jwt"]):
                return response.cookies[cookie_name], f"cookie.{cookie_name}"

        # 3. Dans les headers
        for header_name in ["Authorization", "X-Auth-Token", "X-Access-Token"]:
            if header_name in response.headers:
                return response.headers[header_name], f"header.{header_name}"

        return None, None
