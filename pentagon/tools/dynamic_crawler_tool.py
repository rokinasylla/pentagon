"""
Crawler & fuzzing DYNAMIQUE (navigateur) pour PENTAGON.

PROBLÈME RÉSOLU — la surface d'attaque INVISIBLE à l'analyse statique.
Les outils existants découvrent la cible de façon statique (lecture du bundle
JS, devinette d'endpoints). Or une application moderne (SPA React/Vue/Angular)
ne révèle sa vraie surface qu'À L'EXÉCUTION :
- des pages/routes n'existent qu'après exécution du JS,
- des formulaires/champs n'apparaissent qu'après une action (clic, étape),
- des appels d'API ne partent qu'au clic (XHR/fetch),
- des zones ne sont visibles qu'après connexion.

Cet outil pilote un VRAI navigateur (Playwright) pour explorer l'application
comme un utilisateur (crawler dynamique) : il ne se contente pas de CHARGER les
pages, il MANIPULE l'interface — clique les contrôles (boutons, onglets, menus),
soumet les formulaires avec des valeurs bénignes et, si l'opérateur fournit des
identifiants (autorisés par le RoE), se connecte pour explorer la surface
AUTHENTIFIÉE — pour forcer l'application à révéler ses VRAIS points d'entrée
(XHR/fetch), avec leur méthode et leur corps, au lieu de les deviner
statiquement. Il injecte ensuite des charges de
test dans les points d'entrée découverts et observe la réaction rendue (fuzzing
dynamique). Il cartographie ainsi la surface réelle et lève les faux négatifs
dus aux inputs et aux appels jamais déclenchés sans interaction.

ARCHITECTURE — deux couches nettement séparées :
1. Couche PURE (sans navigateur, testable hors-ligne) : extraction de liens et
   de formulaires depuis du HTML, filtrage de périmètre, déduplication d'URL,
   décision des contrôles sûrs à cliquer/soumettre (liste d'exclusion des
   libellés destructifs), génération de valeurs bénignes de formulaire,
   classification des réponses de fuzzing (signatures d'erreur SQL, réflexion,
   erreur serveur). Tout le raisonnement y vit → tests déterministes.
2. Couche NAVIGATEUR (Playwright, importé de façon différée) : run_dynamic_crawl
   (exploration) et run_dynamic_fuzz (test), qui ne font qu'orchestrer la couche
   pure autour d'un navigateur réel.

GOUVERNANCE (deny-by-default) — chaque URL visitée ou fuzzée est bornée par
`host_in_scope(url, target_url, scope_check)` : le crawler ne sort JAMAIS du
périmètre autorisé, même si une page référence un lien tiers. Le crawling est
une action `active_scan` ; le fuzzing est une action `exploitation`. La
politique vit chez l'appelant (agent Web App / Exploitation / orchestrateur).

GARDE-FOUS ÉTHIQUES :
- Interaction NON destructive : les contrôles et formulaires dont le libellé ou
  l'action évoque une opération irréversible (supprimer, payer, commander, se
  déconnecter, réinitialiser…) ne sont JAMAIS cliqués ni soumis ; les
  formulaires ne sont remplis que de valeurs bénignes, jamais de vraies données.
- Marqueur XSS de PREUVE non nuisible (drapeau `window.<marqueur>=1`), comme
  xss_browser_tool : aucune exfiltration ni défacement.
- Plafonds stricts (max_pages, max_depth, max_clicks, max_form_submits) pour
  rester léger et poli.
- Navigateur isolé, headless par défaut.

Utilisé par : Agent Web App (crawl) et Agent Exploitation (fuzz).
Standards : OWASP WSTG-INFO-07 (Map Execution Paths), WSTG-INPV (Input
Validation), MITRE ATT&CK T1595.003 (Active Scanning: Wordlist Scanning),
T1190 (Exploit Public-Facing Application).

Dépendance : playwright (`pip install playwright && playwright install chromium`).
"""

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urlunparse

from pentagon.core.scope_guard import host_in_scope


# Marqueur d'exécution XSS unique (inerte : pose un drapeau window, rien d'autre).
FUZZ_XSS_MARKER = "PGN_FUZZ_XSS_4k2"

# Signatures d'erreur SQL renvoyées par les SGBD quand une injection casse la
# requête — un signal fort de point d'injection (couche PURE, insensible à la casse).
_SQL_ERROR_SIGNATURES = [
    "sql syntax", "you have an error in your sql", "warning: mysql",
    "mysql_fetch", "mysqli", "unclosed quotation mark",
    "quoted string not properly terminated", "ora-0", "oracle error",
    "postgresql", "pg_query", "psql:", "syntax error at or near",
    "sqlite3.", "sqlite error", "sqlstate", "odbc", "native client",
    "unterminated quoted string",
]

# Charges de fuzzing génériques (pas de donnée spécifique à une cible).
FUZZ_PAYLOADS: dict[str, list[str]] = {
    "sqli": ["'", "' OR '1'='1", "1' ORDER BY 999-- -"],
    "xss": [
        f'<img src=x onerror="window.{FUZZ_XSS_MARKER}=1">',
        f'"><svg onload="window.{FUZZ_XSS_MARKER}=1">',
    ],
    "error": ["%", "../../../etc/passwd", "{{7*7}}"],
}

# Schémas de lien à ignorer (ne mènent pas à une page navigable).
_IGNORED_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "blob:", "sms:", "ftp:")

# Extensions d'asset : repérées comme liens mais jamais crawlées comme des pages.
_ASSET_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip", ".mp4", ".webm",
)

_HREF_RE = re.compile(r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_RE = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r'<(input|textarea|select)\b([^>]*)>', re.IGNORECASE)

# Libellés / chemins d'action DESTRUCTEURS ou IRRÉVERSIBLES : jamais cliqués ni
# soumis automatiquement (FR + EN). Comparés en sous-chaîne, insensibles à la
# casse. « se connecter » reste autorisé (découverte de la surface authentifiée).
DANGEROUS_LABEL_PATTERNS = (
    "supprim", "effac", "delete", "remove", "drop", "purg", "vider",
    "déconnex", "deconnex", "déconnect", "deconnect", "logout", "log out",
    "sign out",
    "payer", "paiement", "payment", "checkout", "commander", "commande",
    "acheter", "achat", "buy", "purchase",
    "réinitialis", "reinitialis", "reset", "désactiv", "desactiv", "deactivate",
    "désabonn", "desabonn", "unsubscribe", "révoqu", "revoqu", "bannir",
    "confirm",
)

# Contrôles interactifs NON-liens à cliquer (les <a href> sont déjà suivis par
# le crawl). Boutons, rôles ARIA cliquables et éléments à gestionnaire onclick.
CLICK_SELECTOR = (
    "button:not([type=submit]), [role=button], [role=tab], [role=menuitem], "
    "[onclick]"
)

# Indices (FR + EN) d'un lien/bouton/chemin de CONNEXION — sert à trouver la
# page de login quand l'opérateur n'en fournit pas l'URL explicite.
LOGIN_PATH_HINTS = (
    "login", "log in", "log-in", "signin", "sign in", "sign-in",
    "connexion", "connect", "connecter", "auth", "identif", "identifier",
)

# Bruit à EXCLURE des candidats de login (générique, aucun site en dur) : les
# URLs de transport temps réel et les assets statiques contiennent parfois
# « login » sans être des endpoints d'authentification (ex. /login/socket.io/…).
_LOGIN_NOISE = (
    "socket.io", "transport=", "/polling", "/websocket", "sockjs",
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".svg", ".ico",
    ".woff", ".gif",
)

# Forme d'un JWT (3 segments base64url, en-tête commençant par « eyJ ») — sert à
# repérer un jeton de session par sa FORME, sans connaître le nom du champ ni le
# site. Utilisé pour la détection universelle de session après connexion.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")

# Indices qu'un champ texte est une BOÎTE DE RECHERCHE (et non l'identifiant du
# login) — générique, aucun site en dur. Sur une SPA, la barre de recherche de
# l'en-tête est souvent le premier `input[type=text]` de la page : la remplir à
# la place de l'e-mail casse la connexion. On l'écarte par ces indices.
_SEARCH_HINTS = (
    "search", "recherche", "rechercher", "query", "find", "filter", "filtre",
    "keyword", "mot-cl", "lookup",
)


# =============================================================================
# Couche PURE (déterministe, sans réseau ni navigateur → testable hors-ligne)
# =============================================================================

def normalize_url(url: str) -> str:
    """
    Normalise (PUR) une URL pour la déduplication du crawl.

    Retire le fragment (#...), abaisse le schéma/hôte en minuscules, et supprime
    la barre finale d'un chemin non racine. Deux URL qui pointent vers la même
    ressource se normalisent ainsi en une seule clé de visite.
    """
    if not url:
        return ""
    parts = urlparse(url.strip())
    scheme = (parts.scheme or "https").lower()
    netloc = parts.netloc.lower()
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return urlunparse((scheme, netloc, path, "", parts.query, ""))


def _attr(attrs: str, name: str) -> str | None:
    """Extrait (PUR) la valeur d'un attribut HTML depuis une chaîne d'attributs."""
    m = re.search(name + r'\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
    return m.group(1) if m else None


def extract_links(html: str, base_url: str) -> list[str]:
    """
    Extrait (PUR) les liens <a href> d'un HTML, résolus en URLs absolues.

    Ignore les schémas non navigables (mailto:, javascript:, ...) et les
    fragments internes. Déduplique en conservant l'ordre d'apparition.
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in _HREF_RE.findall(html or ""):
        href = raw.strip()
        low = href.lower()
        if not href or href.startswith("#") or low.startswith(_IGNORED_SCHEMES):
            continue
        absolute = urljoin(base_url, href).split("#")[0]
        if absolute and absolute not in seen:
            seen.add(absolute)
            out.append(absolute)
    return out


def extract_forms(html: str, base_url: str) -> list[dict[str, Any]]:
    """
    Extrait (PUR) les formulaires d'un HTML : action (absolue), méthode et champs.

    Returns:
        Liste de dicts {"action", "method" (GET|POST), "inputs": [{"name","type"}]}.
        Un formulaire sans action hérite de base_url ; la méthode par défaut est GET.
    """
    forms: list[dict[str, Any]] = []
    for attrs, body in _FORM_RE.findall(html or ""):
        action_val = _attr(attrs, "action")
        action = urljoin(base_url, action_val) if action_val else base_url
        method = (_attr(attrs, "method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"

        inputs: list[dict[str, str]] = []
        seen_names: set[str] = set()
        for tag, iattrs in _INPUT_RE.findall(body):
            name = _attr(iattrs, "name")
            if not name or name in seen_names:
                continue
            seen_names.add(name)
            itype = _attr(iattrs, "type")
            if not itype:
                itype = "textarea" if tag.lower() == "textarea" else "text"
            inputs.append({"name": name, "type": itype.lower()})

        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def is_asset(url: str) -> bool:
    """True (PUR) si l'URL pointe vers un asset (fichier statique), pas une page."""
    path = urlparse(url or "").path.lower()
    return path.endswith(_ASSET_EXTENSIONS)


def in_scope_links(links: list[str], target_url: str, scope_check=None) -> list[str]:
    """
    Filtre (PUR, deny-by-default) une liste de liens au périmètre autorisé.

    Ne conserve que les URLs dont l'hôte est la cible de campagne OU explicitement
    autorisé par le RoE (scope_check). Écarte aussi les assets statiques (inutiles
    à crawler comme des pages). Déduplique par forme normalisée.
    """
    out: list[str] = []
    seen: set[str] = set()
    for link in links:
        if is_asset(link):
            continue
        if not host_in_scope(link, target_url, scope_check):
            continue
        key = normalize_url(link)
        if key and key not in seen:
            seen.add(key)
            out.append(link)
    return out


def build_fuzz_urls(url: str, payload: str) -> list[str]:
    """
    Construit (PUR) les URLs de fuzzing d'une URL donnée pour une charge.

    - Si l'URL porte déjà des paramètres de requête, on remplace la valeur de
      CHAQUE paramètre, tour à tour, par la charge.
    - Sinon, on injecte la charge sur quelques noms de paramètres courants.

    Returns:
        Liste d'URLs (une par point d'injection). Vide si url manquante.
    """
    if not url:
        return []
    parts = urlparse(url)
    query_items = parse_qsl(parts.query, keep_blank_values=True)
    urls: list[str] = []

    if query_items:
        for i in range(len(query_items)):
            mutated = list(query_items)
            mutated[i] = (mutated[i][0], payload)
            new_q = urlencode(mutated, doseq=True)
            urls.append(urlunparse(parts._replace(query=new_q)))
    else:
        for name in ("q", "search", "id", "name", "query"):
            new_q = urlencode([(name, payload)])
            urls.append(urlunparse(parts._replace(query=new_q)))
    return urls


def classify_fuzz_response(
    status_code: int | None,
    body: str | None,
    payload: str,
    xss_executed: bool = False,
    baseline_body: str | None = None,
) -> dict[str, Any]:
    """
    Classe (PUR) la réaction d'une page à une charge de fuzzing.

    Ordre de priorité des signaux (du plus au moins probant) :
      - xss_exec     : le marqueur XSS s'est exécuté dans le DOM (preuve),
      - sql_error    : la charge a INTRODUIT une signature d'erreur SQL,
      - reflection   : la charge est réfléchie telle quelle (XSS potentiel),
      - server_error : la charge a déclenché un HTTP 5xx (point d'injection probable).

    `baseline_body` = réponse « propre » (sans charge) du même point d'entrée.
    Fourni, il sert de RÉFÉRENCE : on ne retient `sql_error`/`reflection` que si
    le signal est NOUVEAU par rapport au baseline. Cela évite les faux positifs
    quand une page contient déjà, en temps normal, une chaîne ressemblant à une
    signature (contenu rendu, libellé, etc.). Omis, l'ancien comportement
    (présence absolue) s'applique.

    Returns:
        {"signal": <str|None>, "severity": <str|None>, "evidence": <str|None>}.
    """
    body_text = body or ""
    low = body_text.lower()
    base_low = (baseline_body or "").lower()
    base_text = baseline_body or ""

    if xss_executed:
        return {
            "signal": "xss_exec",
            "severity": "high",
            "evidence": "La charge injectée s'est RÉELLEMENT exécutée dans le DOM "
                        "(drapeau window positionné) — XSS confirmé.",
        }

    for sig in _SQL_ERROR_SIGNATURES:
        # Signal retenu seulement si la charge a INTRODUIT la signature
        # (présente avec la charge, absente du baseline) → vraie injection.
        if sig in low and sig not in base_low:
            return {
                "signal": "sql_error",
                "severity": "high",
                "evidence": f"La charge a introduit une signature d'erreur SQL « {sig} » "
                            f"absente de la réponse normale (injection SQL probable).",
            }

    if payload and payload in body_text and payload not in base_text:
        return {
            "signal": "reflection",
            "severity": "medium",
            "evidence": "Charge réfléchie telle quelle dans la page sans échappement "
                        "(XSS réfléchi possible — à confirmer par exécution).",
        }

    if isinstance(status_code, int) and status_code >= 500:
        return {
            "signal": "server_error",
            "severity": "low",
            "evidence": f"La charge a déclenché une erreur serveur HTTP {status_code} "
                        f"(entrée mal gérée — point d'injection probable).",
        }

    return {"signal": None, "severity": None, "evidence": None}


def is_dangerous_label(text: str) -> bool:
    """
    True (PUR) si un libellé de contrôle ou un chemin d'action évoque une
    opération DESTRUCTRICE ou irréversible (suppression, paiement, commande,
    déconnexion, réinitialisation…). Ces contrôles ne sont jamais cliqués ni
    soumis automatiquement — garde-fou « prouver, jamais ravager ».
    """
    low = (text or "").lower()
    return any(pat in low for pat in DANGEROUS_LABEL_PATTERNS)


def benign_value_for(name: str, itype: str) -> str:
    """
    Choisit (PUR) une valeur de test BÉNIGNE pour un champ de formulaire, selon
    son type HTML et des indices de nom. Jamais de vraie donnée : on ne cherche
    qu'à déclencher le vrai endpoint derrière le formulaire, pas à usurper.
    """
    n = (name or "").lower()
    t = (itype or "text").lower()
    if t == "email" or "mail" in n:
        return "pentagon-probe@example.com"
    if t == "password" or "pass" in n or "mdp" in n or "pwd" in n:
        return "Pentagon-Probe-7x!"
    if t in ("number", "range") or n in ("age", "qty", "quantity", "quantite"):
        return "1"
    if t == "tel" or "phone" in n or "tel" in n:
        return "+10000000000"
    if t == "url" or n in ("url", "website", "site", "lien"):
        return "https://example.com"
    if t == "date":
        return "2026-01-01"
    if t == "search" or "search" in n or "recherch" in n or n == "q":
        return "pentagon"
    return "pentagon-test"


# Types de champs qu'on NE remplit pas (jetons, boutons, fichiers, cases).
_FILLABLE_SKIP_TYPES = (
    "hidden", "submit", "button", "image", "reset", "file", "checkbox", "radio",
)


def plan_form_fill(form: dict[str, Any]) -> dict[str, Any]:
    """
    Décide (PUR) si un formulaire est sûr à soumettre et avec quelles valeurs.

    Refuse (submit=False) si l'action ou un champ évoque une opération
    destructive, ou si le formulaire n'a aucun champ texte à remplir. Sinon,
    associe à chaque champ remplissable une valeur bénigne (benign_value_for).

    Returns:
        {"submit": bool, "values": {nom: valeur}, "reason": str|None}.
    """
    action = (form or {}).get("action", "") or ""
    inputs = (form or {}).get("inputs", []) or []
    haystack = action + " " + " ".join((i.get("name") or "") for i in inputs)
    if is_dangerous_label(haystack):
        return {"submit": False, "values": {},
                "reason": "action ou champ sensible (potentiellement destructif)"}

    values: dict[str, str] = {}
    for i in inputs:
        name = i.get("name")
        itype = (i.get("type") or "text").lower()
        if not name or itype in _FILLABLE_SKIP_TYPES:
            continue
        values[name] = benign_value_for(name, itype)

    if not values:
        return {"submit": False, "values": {},
                "reason": "aucun champ texte à remplir"}
    return {"submit": True, "values": values, "reason": None}


def looks_like_login_path(text: str) -> bool:
    """
    True (PUR) si une URL/un libellé évoque une page/un lien de CONNEXION, en
    écartant le bruit générique (transport temps réel socket.io/websocket,
    assets statiques) qui contient parfois « login » sans être un endpoint
    d'authentification. Générique : aucune URL propre à un site.
    """
    low = (text or "").lower()
    if any(n in low for n in _LOGIN_NOISE):
        return False
    return any(h in low for h in LOGIN_PATH_HINTS)


def is_search_field(field: dict[str, Any]) -> bool:
    """
    Dit (PUR) si un champ de saisie est une BOÎTE DE RECHERCHE plutôt qu'un
    identifiant de connexion. GÉNÉRIQUE : se fonde sur le type `search` ou sur des
    indices de nom/id/placeholder/aria-label (`_SEARCH_HINTS`), jamais sur un site
    en dur. Sert à ne pas confondre la barre de recherche d'en-tête d'une SPA avec
    le champ e-mail du login.
    """
    if (field.get("type") or "").lower() == "search":
        return True
    hay = " ".join(str(field.get(k) or "") for k in (
        "name", "id", "placeholder", "aria_label", "aria-label",
        "formcontrolname", "autocomplete")).lower()
    return any(h in hay for h in _SEARCH_HINTS)


def pick_login_fields(forms: list[dict[str, Any]]) -> dict[str, Any] | None:
    """
    Choisit (PUR) le formulaire de connexion parmi des formulaires extraits.

    Le formulaire de login est celui qui porte un champ `password` ; l'identifiant
    est le premier champ texte/e-mail (ou au nom évocateur : user/email/login…)
    du même formulaire, en écartant toute boîte de recherche. Les champs cachés
    (jeton CSRF) sont ignorés.

    Returns:
        {"action", "method", "username_field", "password_field"} ou None si aucun
        formulaire ne contient de champ mot de passe.
    """
    for f in forms or []:
        inputs = f.get("inputs", []) or []
        pw = next((i for i in inputs
                   if (i.get("type") or "").lower() == "password"), None)
        if not pw:
            continue
        uname = None
        for i in inputs:
            if i is pw:
                continue
            t = (i.get("type") or "text").lower()
            n = (i.get("name") or "").lower()
            if t in ("hidden", "submit", "button", "checkbox", "radio", "file"):
                continue
            if is_search_field(i):
                continue
            if t in ("text", "email", "tel") or any(
                    h in n for h in ("user", "email", "mail", "login",
                                     "identif", "pseudo")):
                uname = i.get("name")
                break
        return {
            "action": f.get("action"),
            "method": (f.get("method") or "POST").upper(),
            "username_field": uname,
            "password_field": pw.get("name"),
        }
    return None


# Indices d'un contrôle de DÉCONNEXION (apparaît une fois connecté) — signal fort
# de connexion réussie.
_LOGOUT_HINTS = (
    "logout", "log out", "sign out", "déconnex", "deconnex",
    "se déconnecter", "se deconnecter",
)


def login_success_signal(
    before_html: str,
    after_html: str,
    auth_cookie_added: bool = False,
    token_found: bool = False,
) -> dict[str, Any]:
    """
    Juge (PUR) si une tentative de connexion a RÉUSSI, par signaux observables.

    Seuls comptent des ARTEFACTS D'AUTHENTIFICATION positifs — jamais la simple
    disparition du formulaire, qui, sur une SPA, se produit à chaque changement de
    route sans qu'aucune connexion n'ait eu lieu (faux positif observé sur Juice
    Shop : formulaire parti, mais 0 requête de login et aucun jeton). Ordre :
      1. un jeton de session a été capté (`token_found`, p. ex. Bearer JWT),
      2. un cookie de session est apparu après soumission (`auth_cookie_added`),
      3. un contrôle de déconnexion apparaît (absent avant, présent après).

    La disparition du champ mot de passe est renvoyée comme signal FAIBLE
    (`weak_form_gone`) à des fins de diagnostic, mais ne vaut PAS succès.

    Returns:
        {"success": bool, "evidence": str, "weak_form_gone": bool}.
    """
    b = (before_html or "").lower()
    a = (after_html or "").lower()

    had_pw = 'type="password"' in b or "type='password'" in b
    has_pw = 'type="password"' in a or "type='password'" in a
    weak_form_gone = had_pw and not has_pw

    if token_found:
        return {"success": True, "weak_form_gone": weak_form_gone,
                "evidence": "un jeton de session a été capté après connexion"}

    if auth_cookie_added:
        return {"success": True, "weak_form_gone": weak_form_gone,
                "evidence": "un cookie de session est apparu après soumission"}

    if any(h in a for h in _LOGOUT_HINTS) and not any(h in b for h in _LOGOUT_HINTS):
        return {"success": True, "weak_form_gone": weak_form_gone,
                "evidence": "un contrôle de déconnexion est apparu après connexion"}

    if weak_form_gone:
        return {"success": False, "weak_form_gone": True,
                "evidence": "le formulaire a disparu mais aucun artefact "
                            "d'authentification (jeton/cookie) — succès non prouvé"}

    return {"success": False, "weak_form_gone": False,
            "evidence": "aucun signal de connexion réussie détecté"}


def extract_bearer_token(blob: Any) -> str | None:
    """
    Cherche (PUR) un jeton de forme JWT dans une chaîne, ou récursivement dans
    les valeurs d'un dict/d'une liste (ex. localStorage sérialisé, réponse JSON
    de login). GÉNÉRIQUE : repère le jeton par sa FORME (`_JWT_RE`), jamais par un
    nom de champ propre à un site. Retourne le premier jeton trouvé, ou None.
    """
    if isinstance(blob, str):
        m = _JWT_RE.search(blob)
        return m.group(0) if m else None
    if isinstance(blob, dict):
        for v in blob.values():
            t = extract_bearer_token(v)
            if t:
                return t
        return None
    if isinstance(blob, (list, tuple)):
        for v in blob:
            t = extract_bearer_token(v)
            if t:
                return t
        return None
    return None


def extract_endpoints(crawl_result: dict[str, Any]) -> dict[str, Any]:
    """
    Extrait (PUR) de la sortie de run_dynamic_crawl le catalogue d'endpoints
    RÉELS observés en manipulant l'interface — prêt à alimenter l'exploitation
    au lieu de deviner les endpoints statiquement.

    - api_endpoints : URLs des appels XHR/fetch réellement émis (dédupliquées).
    - app_routes    : chemins des pages visitées + actions de formulaire.
    - login_urls    : endpoints d'authentification (déclencheur « login », allure
                      de login, ou bloc `login` du crawl).
    - catalog       : chaque appel observé, avec method/url/body/content_type/
                      trigger (preuve : quelle action a révélé quel endpoint).

    Returns:
        {"api_endpoints", "app_routes", "login_urls", "catalog"}.
    """
    out: dict[str, Any] = {
        "api_endpoints": [], "app_routes": [], "login_urls": [], "catalog": [],
        "session": None}
    if not isinstance(crawl_result, dict):
        return out
    seen_api: set[str] = set()
    seen_route: set[str] = set()
    seen_login: set[str] = set()

    for call in crawl_result.get("api_calls", []) or []:
        if not isinstance(call, dict):
            continue
        url = call.get("url")
        if not url:
            continue
        if url not in seen_api:
            seen_api.add(url)
            out["api_endpoints"].append(url)
        out["catalog"].append({
            "method": call.get("method"),
            "url": url,
            "body": call.get("body"),
            "content_type": call.get("content_type"),
            "trigger": call.get("trigger"),
        })
        trig = (call.get("trigger") or "").lower()
        if (trig.startswith("login") or looks_like_login_path(url)) \
                and url not in seen_login:
            seen_login.add(url)
            out["login_urls"].append(url)

    for pg in crawl_result.get("pages", []) or []:
        u = pg.get("url") if isinstance(pg, dict) else None
        if u and u not in seen_route:
            seen_route.add(u)
            out["app_routes"].append(u)

    for f in crawl_result.get("forms", []) or []:
        a = f.get("action") if isinstance(f, dict) else None
        if a and a not in seen_route:
            seen_route.add(a)
            out["app_routes"].append(a)
        if a and looks_like_login_path(a) and a not in seen_login:
            seen_login.add(a)
            out["login_urls"].append(a)

    login = crawl_result.get("login") or {}
    lu = login.get("login_url") if isinstance(login, dict) else None
    if lu and lu not in seen_login:
        seen_login.add(lu)
        out["login_urls"].append(lu)

    # Session authentifiée captée par le crawler (jeton Bearer / cookies).
    sess = login.get("session") if isinstance(login, dict) else None
    if isinstance(sess, dict) and (sess.get("token") or sess.get("cookies")):
        out["session"] = sess

    return out


# =============================================================================
# Couche NAVIGATEUR (Playwright, import différé → module importable hors-ligne)
# =============================================================================

def _click_controls(page, page_url, target_url, scope_check, ctx, result,
                    budget, nav_timeout_ms, settle_ms):
    """
    (NAVIGATEUR) Clique un ensemble BORNÉ de contrôles interactifs non-liens de
    la page courante pour déclencher les routes/appels d'API cachés derrière une
    action. Ignore les contrôles au libellé destructif (is_dangerous_label) et
    revient à `page_url` si un clic a quitté la page (préserve le périmètre et la
    stabilité). Les appels captés le sont par le gestionnaire réseau global.
    """
    clicked = 0
    scanned = 0
    scan_cap = max(40, budget * 6)
    while clicked < budget and scanned < scan_cap:
        try:
            els = page.query_selector_all(CLICK_SELECTOR)
        except Exception:
            break
        if scanned >= len(els):
            break
        el = els[scanned]
        scanned += 1
        try:
            label = (el.inner_text() or el.get_attribute("aria-label")
                     or el.get_attribute("value") or el.get_attribute("title")
                     or "").strip()
        except Exception:
            continue  # élément périmé par un rendu précédent
        if is_dangerous_label(label):
            continue
        try:
            if not (el.is_visible() and el.is_enabled()):
                continue
        except Exception:
            continue
        before = len(result["api_calls"])
        ctx["trigger"] = ("clic:" + label[:40]) if label else "clic"
        try:
            el.click(timeout=3000)
            page.wait_for_timeout(settle_ms)
        except Exception:
            continue
        clicked += 1
        result["interactions"].append({
            "action": "click",
            "label": label[:60],
            "new_api_calls": len(result["api_calls"]) - before,
        })
        # Revenir si le clic a navigué ailleurs (reste in-scope, DOM stable).
        try:
            if normalize_url(page.url) != normalize_url(page_url):
                page.goto(page_url, wait_until="load", timeout=nav_timeout_ms)
                page.wait_for_timeout(settle_ms)
        except Exception:
            pass
    ctx["trigger"] = "load"


def _fill_and_submit_forms(page, page_url, forms, target_url, scope_check, ctx,
                           result, budget, nav_timeout_ms, settle_ms):
    """
    (NAVIGATEUR) Remplit de valeurs bénignes puis soumet un ensemble BORNÉ de
    formulaires in-scope et non destructifs (plan_form_fill), pour capter le VRAI
    endpoint (méthode + corps) qui se trouve derrière. Recharge `page_url` avant
    chaque formulaire (il doit être présent), soumet par le bouton de soumission
    ou, à défaut, par Entrée. Les appels captés le sont par le gestionnaire
    réseau global.
    """
    submitted = 0
    for form in forms or []:
        if submitted >= budget:
            break
        action = form.get("action", "")
        if not host_in_scope(action, target_url, scope_check):
            continue
        plan = plan_form_fill(form)
        if not plan["submit"]:
            result["interactions"].append(
                {"action": "form_skip", "target": action, "reason": plan["reason"]})
            continue

        try:
            page.goto(page_url, wait_until="load", timeout=nav_timeout_ms)
            page.wait_for_timeout(settle_ms)
        except Exception:
            continue

        filled = 0
        last_name = None
        for name, val in plan["values"].items():
            try:
                loc = page.locator(f'[name="{name}"]').first
                loc.fill(val, timeout=2000)
                filled += 1
                last_name = name
            except Exception:
                continue
        if filled == 0:
            continue

        before = len(result["api_calls"])
        ctx["trigger"] = "form:" + (urlparse(action).path or "/")
        done = False
        try:
            btn = page.locator(
                "button[type=submit], input[type=submit], form button").first
            if btn.count() > 0:
                try:
                    blabel = (btn.inner_text() or "").strip()
                except Exception:
                    blabel = ""
                if not is_dangerous_label(blabel):
                    btn.click(timeout=3000)
                    done = True
        except Exception:
            done = False
        if not done and last_name:
            try:
                page.locator(f'[name="{last_name}"]').first.press(
                    "Enter", timeout=2000)
                done = True
            except Exception:
                done = False
        page.wait_for_timeout(settle_ms)

        submitted += 1
        result["interactions"].append({
            "action": "form_submit",
            "target": action,
            "fields": sorted(plan["values"].keys()),
            "new_api_calls": len(result["api_calls"]) - before,
            "submitted": done,
        })
    ctx["trigger"] = "load"


# (NAVIGATEUR) Sélection de l'identifiant par le DOM — robuste sur les SPA où les
# champs n'ont pas d'attribut `name` (Angular/React : id, placeholder,
# aria-label, formcontrolname). GÉNÉRIQUE : s'ancre sur le champ mot de passe,
# écarte les boîtes de recherche, et préfère le type e-mail puis le champ texte
# le plus PROCHE EN AMONT du mot de passe (évite la barre de recherche d'en-tête,
# premier `input[type=text]` de la page sur beaucoup de SPA). Marque le champ
# retenu d'un attribut repère → rempli ensuite par Playwright (vrais events).
_USERNAME_PICKER_JS = r"""
() => {
  const SEARCH = /search|recherche|rechercher|query|\bfind\b|filter|filtre|keyword|lookup/i;
  const SKIP = ['password','hidden','submit','button','checkbox','radio','file','range','color','image','reset'];
  const pw = document.querySelector('input[type=password]');
  const all = Array.from(document.querySelectorAll('input, textarea'));
  const pwIdx = pw ? all.indexOf(pw) : all.length;
  const visible = (e) => { const r = e.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden'; };
  const isSearch = (e) => {
    if ((e.type || '').toLowerCase() === 'search') return true;
    const hay = [e.id, e.name, e.placeholder, e.getAttribute('aria-label'),
                 e.getAttribute('formcontrolname'), e.autocomplete].join(' ').toLowerCase();
    return SEARCH.test(hay);
  };
  const cand = [];
  all.forEach((e, i) => {
    if (e === pw) return;
    const t = (e.type || 'text').toLowerCase();
    if (e.tagName === 'INPUT' && SKIP.includes(t)) return;
    if (!visible(e)) return;
    if (isSearch(e)) return;
    cand.push({ e, i, t });
  });
  if (!cand.length) return false;
  const score = (c) => {
    let s = 0;
    if (c.t === 'email') s += 1000;                 // e-mail = identifiant le plus probable
    const hay = [c.e.id, c.e.name, c.e.placeholder,
                 c.e.getAttribute('aria-label'), c.e.autocomplete].join(' ').toLowerCase();
    if (/user|email|mail|login|identif|pseudo|account|compte/.test(hay)) s += 500;
    if (c.i < pwIdx) s += 200 - (pwIdx - c.i);       // le plus proche EN AMONT du mot de passe
    else s += -(c.i - pwIdx);
    return s;
  };
  cand.sort((a, b) => score(b) - score(a));
  const chosen = cand[0].e;
  chosen.setAttribute('data-pentagon-uname', '1');
  return true;
}
"""


def _perform_login(page, target_url, scope_check, creds, ctx, nav_timeout_ms,
                   settle_ms):
    """
    (NAVIGATEUR) Connecte le navigateur avec les identifiants FOURNIS par
    l'opérateur (autorisés par le RoE), pour débloquer la surface authentifiée.
    La session (cookie) persiste dans le contexte → tout le crawl qui suit est
    authentifié. Ne tente rien sans identifiants ; reste borné au périmètre.

    Étapes : trouver la page de login (URL fournie, sinon lien d'allure login,
    sinon la cible), afficher le formulaire (clic d'un lien « connexion » si SPA),
    remplir identifiant + mot de passe, soumettre, puis juger le succès par
    signaux observables (cookie apparu / déconnexion visible / formulaire parti).

    Returns:
        {"attempted", "success", "login_url", "evidence"}.
    """
    out = {"attempted": False, "success": False, "login_url": None,
           "evidence": None}
    if not creds:
        return out
    username = creds.get("username")
    password = creds.get("password")
    if not username or not password:
        out["evidence"] = "identifiants incomplets (username/password requis)"
        return out

    # 1) Déterminer l'URL de login (bornée au périmètre).
    login_url = creds.get("login_url")
    if not login_url:
        try:
            html0 = page.content()
        except Exception:
            html0 = ""
        for href in extract_links(html0, page.url):
            if looks_like_login_path(href) and \
                    host_in_scope(href, target_url, scope_check):
                login_url = href
                break
    if not login_url:
        login_url = target_url  # SPA : le formulaire peut vivre sur l'accueil
    if not host_in_scope(login_url, target_url, scope_check):
        out["evidence"] = "URL de login hors périmètre (refusée)"
        return out
    out["login_url"] = login_url
    out["attempted"] = True

    # 2) Aller sur la page de login.
    try:
        page.goto(login_url, wait_until="load", timeout=nav_timeout_ms)
        page.wait_for_timeout(settle_ms)
    except Exception:
        out["evidence"] = "navigation vers la page de login échouée"
        return out

    # 2bis) SPA : laisser le formulaire se rendre (Angular/React) ; s'il n'apparaît
    # pas, cliquer un lien/bouton « connexion » pour l'afficher.
    try:
        page.wait_for_selector("input[type=password]",
                               timeout=min(nav_timeout_ms, 5000))
    except Exception:
        pass
    try:
        if not page.query_selector("input[type=password]"):
            for el in page.query_selector_all("a, button, [role=button]"):
                try:
                    lab = (el.inner_text() or el.get_attribute("aria-label")
                           or "").strip()
                except Exception:
                    continue
                if looks_like_login_path(lab) and not is_dangerous_label(lab):
                    try:
                        el.click(timeout=3000)
                        page.wait_for_selector("input[type=password]", timeout=3000)
                    except Exception:
                        pass
                    break
    except Exception:
        pass

    # Lecture (NAVIGATEUR) du web storage → jeton Bearer par FORME (JWT).
    def _read_storage_token():
        try:
            store = page.evaluate(
                "() => { const d={};"
                " try{for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);"
                "d['L:'+k]=localStorage.getItem(k);}}catch(e){}"
                " try{for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);"
                "d['S:'+k]=sessionStorage.getItem(k);}}catch(e){}"
                " return d; }")
        except Exception:
            store = {}
        return extract_bearer_token(store), store

    # 3) Repérer les champs. Priorité : nom fourni par l'opérateur > nom détecté
    #    dans un <form> parsé > sélection DOM (robuste sur les SPA sans `name`).
    try:
        before_html = page.content()
    except Exception:
        before_html = ""
    try:
        cookies_before = {c.get("name") for c in page.context.cookies()}
    except Exception:
        cookies_before = set()

    picked = pick_login_fields(extract_forms(before_html, page.url)) or {}
    uname_field = creds.get("username_field") or picked.get("username_field")
    pw_field = creds.get("password_field") or picked.get("password_field")

    uname_filled = False
    try:
        if uname_field:
            page.locator(f'[name="{uname_field}"]').first.fill(
                username, timeout=3000)
            uname_filled = True
        elif page.evaluate(_USERNAME_PICKER_JS):
            page.locator('[data-pentagon-uname="1"]').first.fill(
                username, timeout=3000)
            uname_filled = True
    except Exception:
        uname_filled = False
    if not uname_filled:
        # Dernier recours : 1er champ e-mail, sinon 1er champ texte (peut viser
        # une barre de recherche — d'où la sélection DOM privilégiée au-dessus).
        try:
            loc = page.locator("input[type=email]").first
            if loc.count() == 0:
                loc = page.locator("input[type=text]").first
            if loc.count() > 0:
                loc.fill(username, timeout=3000)
        except Exception:
            pass

    filled_pw = False
    try:
        if pw_field:
            page.locator(f'[name="{pw_field}"]').first.fill(password, timeout=3000)
            filled_pw = True
        else:
            loc = page.locator("input[type=password]").first
            if loc.count() > 0:
                loc.fill(password, timeout=3000)
                filled_pw = True
    except Exception:
        filled_pw = False
    if not filled_pw:
        out["evidence"] = "champ de mot de passe introuvable"
        return out

    # 4) Soumettre (l'appel d'auth réel est capté, étiqueté « login »). On vise le
    #    bouton d'envoi DU FORMULAIRE du mot de passe (pas n'importe quel bouton),
    #    en écartant les libellés dangereux ; à défaut, Entrée dans le mot de passe.
    ctx["trigger"] = "login"
    submitted = False
    try:
        pw_loc = page.locator("input[type=password]").first
        btn = None
        try:
            form = pw_loc.locator("xpath=ancestor::form[1]")
            if form.count() > 0:
                cand = form.locator(
                    "button[type=submit], input[type=submit], button:not([type])")
                if cand.count() > 0:
                    btn = cand.first
        except Exception:
            btn = None
        if btn is None:
            cand = page.locator("button[type=submit], input[type=submit]")
            if cand.count() > 0:
                btn = cand.first
        if btn is not None:
            try:
                lab = (btn.inner_text() or btn.get_attribute("aria-label") or "")
            except Exception:
                lab = ""
            if not is_dangerous_label(lab):
                try:
                    btn.click(timeout=3000)
                    submitted = True
                except Exception:
                    submitted = False
        if not submitted:
            pw_loc.press("Enter", timeout=3000)
            submitted = True
    except Exception:
        pass
    # Laisser partir l'appel d'auth et le jeton s'écrire dans le storage.
    page.wait_for_timeout(max(settle_ms, 1500))
    ctx["trigger"] = "load"

    # 5) Capter la session AVANT de juger : cookies + jeton Bearer (forme JWT) dans
    #    localStorage/sessionStorage — générique, sans nom de champ ni site en dur.
    session: dict[str, Any] = {"token": None, "token_source": None, "cookies": {}}
    try:
        session["cookies"] = {c.get("name"): c.get("value")
                              for c in page.context.cookies() if c.get("name")}
    except Exception:
        pass
    tok, _store = _read_storage_token()
    if not tok:
        # Le jeton peut s'écrire avec un léger décalage après la réponse d'auth.
        page.wait_for_timeout(settle_ms)
        tok, _store = _read_storage_token()
    if tok:
        session["token"] = tok
        session["token_source"] = "web_storage"

    # 6) Juger le succès sur des ARTEFACTS d'auth (jeton/cookie/déconnexion),
    #    jamais sur la seule disparition du formulaire (faux positif SPA).
    try:
        after_html = page.content()
    except Exception:
        after_html = ""
    try:
        cookies_after = {c.get("name") for c in page.context.cookies()}
    except Exception:
        cookies_after = set()
    sig = login_success_signal(
        before_html, after_html,
        auth_cookie_added=bool(cookies_after - cookies_before),
        token_found=bool(tok))
    out["success"] = sig["success"]
    out["evidence"] = sig["evidence"]
    out["session"] = session
    return out


def run_dynamic_crawl(
    target_url: str,
    scope_check=None,
    max_pages: int = 20,
    max_depth: int = 2,
    headless: bool = True,
    nav_timeout_ms: int = 15000,
    settle_ms: int = 600,
    interact: bool = True,
    max_clicks: int = 8,
    submit_forms: bool = True,
    max_form_submits: int = 5,
    credentials: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Explore dynamiquement l'application en pilotant un navigateur réel.

    Parcours en largeur (BFS) depuis target_url. Pour chaque page : exécute le
    JS, collecte les liens <a> et les formulaires rendus, puis MANIPULE la page
    (clique les contrôles, soumet les formulaires avec des valeurs bénignes) pour
    déclencher et capter les appels d'API réels (XHR/fetch, méthode + corps) que
    l'analyse statique et le simple chargement ratent. Ne suit et n'agit QUE dans
    le périmètre autorisé (deny-by-default via host_in_scope).

    Args:
        target_url: URL de départ (= périmètre implicite).
        scope_check: callable (url) -> {"allowed": bool} (le RoE). Deny-by-default.
        max_pages: plafond de pages visitées.
        max_depth: profondeur maximale de suivi des liens.
        headless: navigateur sans interface (True en serveur/CI).
        nav_timeout_ms: délai de navigation par page.
        settle_ms: temps laissé au JS/XHR après chargement.
        interact: si True, MANIPULE la page (clique les contrôles non-liens) pour
            déclencher les routes/appels d'API cachés derrière une action.
        max_clicks: nombre maximal de contrôles cliqués par page.
        submit_forms: si True, remplit les formulaires de valeurs bénignes et les
            soumet pour capter le vrai endpoint (méthode + corps) derrière. Les
            formulaires destructifs sont ignorés (plan_form_fill).
        max_form_submits: nombre maximal de formulaires soumis par page.
        credentials: identifiants FOURNIS par l'opérateur (autorisés par le RoE)
            pour se connecter AVANT le crawl et explorer la surface authentifiée.
            Dict {"username", "password", optionnel "login_url",
            "username_field", "password_field"}. Absent → aucune connexion.

    Returns:
        Dict : status, target_url, login (résultat de la connexion), pages_visited,
        pages, forms, api_calls (chaque appel : method, url, body, content_type,
        trigger), interactions (trace des clics/soumissions), out_of_scope_skipped,
        duration_seconds, error.
    """
    started_at = datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "tool": "dynamic_crawler",
        "status": "success",
        "target_url": target_url,
        "login": None,
        "pages_visited": 0,
        "pages": [],
        "forms": [],
        "api_calls": [],
        "interactions": [],
        "out_of_scope_skipped": 0,
        "duration_seconds": None,
        "error": None,
    }

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        result["status"] = "error"
        result["error"] = ("Playwright non installé. Installez-le : "
                           "pip install playwright && playwright install chromium")
        return result

    api_seen: set[str] = set()
    forms_seen: set[str] = set()
    # Contexte d'interaction courant : étiquette la provenance de chaque appel
    # capté ("load", "clic:…", "form:…") pour la traçabilité (preuve).
    ctx: dict[str, str] = {"trigger": "load"}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            context = browser.new_context()
            page = context.new_page()

            # Interception réseau : on capte les appels d'API déclenchés par le JS
            # (xhr/fetch), bornés au périmètre autorisé.
            def _on_request(req):
                try:
                    if req.resource_type in ("xhr", "fetch") and \
                            host_in_scope(req.url, target_url, scope_check):
                        key = f"{req.method} {req.url.split('#')[0]}"
                        if key not in api_seen:
                            api_seen.add(key)
                            body = None
                            try:
                                body = req.post_data
                            except Exception:
                                body = None
                            # Ne JAMAIS conserver le secret d'identifiant capté
                            # dans un corps (ex. requête de login) : il finirait
                            # dans le JSON/rapport de campagne.
                            _pw = (credentials or {}).get("password")
                            if _pw and body and _pw in body:
                                body = body.replace(_pw, "***REDACTED***")
                            if body and len(body) > 500:
                                body = body[:500] + "…"
                            ctype = None
                            try:
                                ctype = req.headers.get("content-type")
                            except Exception:
                                ctype = None
                            result["api_calls"].append({
                                "method": req.method,
                                "url": req.url.split("#")[0],
                                "body": body,
                                "content_type": ctype,
                                "trigger": ctx["trigger"],
                            })
                        # Backfill GÉNÉRIQUE d'un jeton de session : une requête
                        # in-scope portant « Authorization: Bearer » révèle le
                        # jeton de la surface authentifiée (hors dédup des appels,
                        # pour les SPA qui gardent le jeton en mémoire).
                        try:
                            authz = req.headers.get("authorization")
                            if authz and authz.lower().startswith("bearer ") \
                                    and isinstance(result.get("login"), dict):
                                sess = result["login"].setdefault(
                                    "session",
                                    {"token": None, "token_source": None, "cookies": {}})
                                if not sess.get("token"):
                                    sess["token"] = authz.split(" ", 1)[1].strip()
                                    sess["token_source"] = "authorization_header"
                        except Exception:
                            pass
                except Exception:
                    pass

            page.on("request", _on_request)

            # Connexion préalable (si identifiants fournis) : la session persiste
            # dans le contexte → tout le crawl qui suit explore la surface
            # AUTHENTIFIÉE. On part de la cible, désormais connecté.
            if credentials:
                try:
                    page.goto(target_url, wait_until="load", timeout=nav_timeout_ms)
                    page.wait_for_timeout(settle_ms)
                except Exception:
                    pass
                result["login"] = _perform_login(
                    page, target_url, scope_check, credentials, ctx,
                    nav_timeout_ms, settle_ms)

            queue: list[tuple[str, int]] = [(target_url, 0)]
            visited: set[str] = set()

            while queue and len(visited) < max_pages:
                url, depth = queue.pop(0)
                key = normalize_url(url)
                if not key or key in visited:
                    continue
                visited.add(key)

                try:
                    page.goto(url, wait_until="networkidle", timeout=nav_timeout_ms)
                except Exception:
                    try:
                        page.goto(url, wait_until="load", timeout=nav_timeout_ms)
                    except Exception:
                        continue
                page.wait_for_timeout(settle_ms)

                try:
                    html = page.content()
                except Exception:
                    continue

                links = extract_links(html, url)
                forms = extract_forms(html, url)
                result["pages"].append({
                    "url": url, "depth": depth,
                    "n_links": len(links), "n_forms": len(forms),
                })

                # Formulaires DANS le périmètre uniquement (dédupliqués).
                for f in forms:
                    if host_in_scope(f["action"], target_url, scope_check):
                        fkey = f"{f['method']} {normalize_url(f['action'])} " \
                               f"{sorted(i['name'] for i in f['inputs'])}"
                        if fkey not in forms_seen:
                            forms_seen.add(fkey)
                            result["forms"].append(f)

                # Comptabilise les liens hors périmètre écartés (traçabilité).
                in_scope = in_scope_links(links, target_url, scope_check)
                result["out_of_scope_skipped"] += max(
                    0, len([l for l in links if not is_asset(l)]) - len(in_scope))

                # === MANIPULATION de l'interface — le cœur : trouver les VRAIS
                # endpoints en AGISSANT (clic + soumission), pas en les supposant.
                if interact:
                    _click_controls(page, url, target_url, scope_check, ctx,
                                    result, max_clicks, nav_timeout_ms, settle_ms)
                if submit_forms and forms:
                    _fill_and_submit_forms(page, url, forms, target_url,
                                           scope_check, ctx, result,
                                           max_form_submits, nav_timeout_ms,
                                           settle_ms)

                if depth < max_depth:
                    for link in in_scope:
                        if normalize_url(link) not in visited:
                            queue.append((link, depth + 1))

            context.close()
            browser.close()

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"

    result["pages_visited"] = len(result["pages"])
    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    return result


def run_dynamic_fuzz(
    target_url: str,
    endpoints: list[str],
    scope_check=None,
    categories: tuple[str, ...] = ("sqli", "xss", "error"),
    headless: bool = True,
    nav_timeout_ms: int = 15000,
    settle_ms: int = 400,
    max_endpoints: int = 25,
) -> dict[str, Any]:
    """
    Fuzze dynamiquement des points d'entrée paramétrés en pilotant un navigateur.

    Pour chaque endpoint DANS le périmètre, on construit des URLs de fuzzing
    (une charge par paramètre), on navigue, puis on classe la réaction RENDUE
    (erreur SQL, réflexion, exécution XSS via marqueur, erreur serveur).

    ⚠️ Action `exploitation` : n'émettre que vers une cible autorisée (RoE). La
    garde de périmètre (deny-by-default) écarte tout endpoint hors scope.

    Args:
        target_url: cible de campagne (périmètre).
        endpoints: URLs/chemins à fuzzer (issus du crawl ou de l'analyse JS).
        scope_check: callable (url) -> {"allowed": bool} (le RoE).
        categories: familles de charges à essayer (clés de FUZZ_PAYLOADS).
        max_endpoints: plafond d'endpoints fuzzés.

    Returns:
        Dict : status, endpoints_fuzzed, findings, duration_seconds, error.
    """
    started_at = datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "tool": "dynamic_fuzzer",
        "status": "success",
        "target_url": target_url,
        "endpoints_fuzzed": 0,
        "findings": [],
        "duration_seconds": None,
        "error": None,
    }

    # Périmètre d'abord (deny-by-default), puis plafond.
    in_scope = [
        urljoin(target_url, e) if not e.startswith("http") else e
        for e in (endpoints or [])
    ]
    in_scope = [u for u in in_scope if host_in_scope(u, target_url, scope_check)]
    # Déduplique par forme normalisée.
    seen: set[str] = set()
    targets: list[str] = []
    for u in in_scope:
        k = normalize_url(u)
        if k not in seen:
            seen.add(k)
            targets.append(u)
    targets = targets[:max_endpoints]

    if not targets:
        result["duration_seconds"] = (
            datetime.now(timezone.utc) - started_at).total_seconds()
        return result

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        result["status"] = "error"
        result["error"] = "Playwright non installé."
        return result

    payloads: list[tuple[str, str]] = [
        (cat, pl) for cat in categories for pl in FUZZ_PAYLOADS.get(cat, [])
    ]

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            page = browser.new_context().new_page()

            dialog_fired = {"value": False}
            page.on("dialog", lambda d: (dialog_fired.__setitem__("value", True), d.dismiss()))

            for endpoint in targets:
                result["endpoints_fuzzed"] += 1

                # Réponse de RÉFÉRENCE (sans charge) : sert à ne retenir que les
                # signaux que la charge INTRODUIT (anti-faux-positifs).
                baseline_body = ""
                try:
                    page.goto("about:blank")
                    page.goto(endpoint, wait_until="load", timeout=nav_timeout_ms)
                    page.wait_for_timeout(settle_ms)
                    baseline_body = page.content()
                except Exception:
                    baseline_body = ""

                strong = False  # un signal fort suffit à marquer l'endpoint
                for category, payload in payloads:
                    if strong:
                        break
                    for fuzz_url in build_fuzz_urls(endpoint, payload):
                        if not host_in_scope(fuzz_url, target_url, scope_check):
                            continue
                        dialog_fired["value"] = False
                        try:
                            page.goto("about:blank")
                            page.goto(fuzz_url, wait_until="load", timeout=nav_timeout_ms)
                            page.wait_for_timeout(settle_ms)
                            status_code = None  # le code n'est pas exposé simplement ici
                            body = page.content()
                            xss = dialog_fired["value"] or bool(
                                page.evaluate(f"() => window.{FUZZ_XSS_MARKER} === 1"))
                        except Exception:
                            continue

                        verdict = classify_fuzz_response(
                            status_code, body, payload, xss, baseline_body=baseline_body)
                        if verdict["signal"]:
                            result["findings"].append({
                                "signal": verdict["signal"],
                                "severity": verdict["severity"],
                                "category": category,
                                "url": fuzz_url,
                                "payload": payload,
                                "evidence": verdict["evidence"],
                            })
                            # Un signal fort par endpoint suffit : on arrête là.
                            if verdict["signal"] in ("xss_exec", "sql_error"):
                                strong = True
                                break

            browser.close()

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"

    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    return result
