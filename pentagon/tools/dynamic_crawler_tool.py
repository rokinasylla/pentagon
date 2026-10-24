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
comme un utilisateur (crawler dynamique), puis injecte des charges de test dans
les points d'entrée découverts et observe la réaction rendue (fuzzing
dynamique). Il cartographie ainsi la surface réelle et lève des faux négatifs
dus aux inputs jamais découverts statiquement.

ARCHITECTURE — deux couches nettement séparées :
1. Couche PURE (sans navigateur, testable hors-ligne) : extraction de liens et
   de formulaires depuis du HTML, filtrage de périmètre, déduplication d'URL,
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
- Marqueur XSS de PREUVE non nuisible (drapeau `window.<marqueur>=1`), comme
  xss_browser_tool : aucune exfiltration ni défacement.
- Plafonds stricts (max_pages, max_depth, max_forms) pour rester léger et poli.
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


# =============================================================================
# Couche NAVIGATEUR (Playwright, import différé → module importable hors-ligne)
# =============================================================================

def run_dynamic_crawl(
    target_url: str,
    scope_check=None,
    max_pages: int = 20,
    max_depth: int = 2,
    headless: bool = True,
    nav_timeout_ms: int = 15000,
    settle_ms: int = 600,
) -> dict[str, Any]:
    """
    Explore dynamiquement l'application en pilotant un navigateur réel.

    Parcours en largeur (BFS) depuis target_url. Pour chaque page : exécute le
    JS, collecte les liens <a> et les formulaires rendus, et capte les appels
    d'API déclenchés (XHR/fetch) via l'interception réseau. Ne suit QUE les liens
    dans le périmètre autorisé (deny-by-default via host_in_scope).

    Args:
        target_url: URL de départ (= périmètre implicite).
        scope_check: callable (url) -> {"allowed": bool} (le RoE). Deny-by-default.
        max_pages: plafond de pages visitées.
        max_depth: profondeur maximale de suivi des liens.
        headless: navigateur sans interface (True en serveur/CI).
        nav_timeout_ms: délai de navigation par page.
        settle_ms: temps laissé au JS/XHR après chargement.

    Returns:
        Dict : status, target_url, pages_visited, pages, forms, api_calls,
        out_of_scope_skipped, duration_seconds, error.
    """
    started_at = datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "tool": "dynamic_crawler",
        "status": "success",
        "target_url": target_url,
        "pages_visited": 0,
        "pages": [],
        "forms": [],
        "api_calls": [],
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
                            result["api_calls"].append(
                                {"method": req.method, "url": req.url.split("#")[0]})
                except Exception:
                    pass

            page.on("request", _on_request)

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
