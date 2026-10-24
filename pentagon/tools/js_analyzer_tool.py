"""
Outil d'analyse de bundle JavaScript pour PENTAGON.

Cet outil télécharge la page d'une cible web, identifie automatiquement
les fichiers JavaScript chargés (bundles SPA), les analyse et en extrait :
- Les endpoints d'API référencés
- Les URLs de backend (architectures découplées)
- Les routes de l'application
- Les mots-clés et secrets potentiels

Conçu pour être GÉNÉRIQUE : fonctionne sur toute SPA (React, Vue, Angular)
sans configuration spécifique à une cible.

Utilisé par : Agent Web App (PTES phase 4 — Vulnerability Analysis)
Standards :
- OWASP WSTG-INFO-08 (Map Application Architecture)
- OWASP WSTG-CLNT (Client-side Testing)
- MITRE ATT&CK T1592.002 (Gather Victim Host Information: Software)

Niveau de risque : PASSIF (téléchargement de ressources publiques uniquement)
"""

import re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from typing import Any

# Import DIFFÉRÉ de `requests` (voir run_js_analysis) : le module s'importe sans
# la lib réseau, ce qui rend les fonctions PURES (extraction, filtrage)
# testables hors-ligne — conforme à la convention PENTAGON.
from pentagon.core.scope_guard import same_site, host_of


DEFAULT_TIMEOUT = 30
DEFAULT_HEADERS = {"User-Agent": "PENTAGON-WebApp-Agent/1.0"}


def run_js_analysis(
    target_url: str,
    max_bundles: int = 10,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Analyse les bundles JavaScript d'une cible web pour en extraire
    les endpoints, URLs backend et indices sensibles.
    
    Args:
        target_url: URL de la cible (ex: "https://exemple.com")
        max_bundles: nombre maximum de bundles JS à analyser.
        timeout: délai d'attente par requête.
    
    Returns:
        Dictionnaire structuré contenant :
        - status: "success", "partial" ou "error"
        - target_url: URL analysée
        - bundles_found: liste des fichiers JS découverts
        - bundles_analyzed: nombre de bundles effectivement analysés
        - api_endpoints: chemins d'API découverts (ex: /api/users)
        - app_routes: routes frontend découvertes (ex: /login, /admin)
        - backend_urls: URLs de backend externes (architectures découplées)
        - sensitive_keywords: mots-clés sensibles et leur fréquence
        - potential_secrets: chaînes ressemblant à des secrets/tokens
        - error: message d'erreur le cas échéant
    """
    import requests  # import différé : la lib réseau n'est chargée qu'à l'exécution

    started_at = datetime.now(timezone.utc)

    result: dict[str, Any] = {
        "status": "success",
        "target_url": target_url,
        "bundles_found": [],
        "bundles_analyzed": 0,
        "api_endpoints": [],
        "app_routes": [],
        "backend_urls": [],
        "sensitive_keywords": {},
        "potential_secrets": [],
        "duration_seconds": None,
        "error": None,
    }
    
    # Normalise l'URL (ajoute https:// si absent)
    if not target_url.startswith("http"):
        target_url = f"https://{target_url}"
        result["target_url"] = target_url
    
    try:
        # 1. Télécharge la page d'accueil
        page_response = requests.get(
            target_url,
            timeout=timeout,
            headers=DEFAULT_HEADERS,
        )
        
        if page_response.status_code != 200:
            result["status"] = "error"
            result["error"] = f"Page principale inaccessible (HTTP {page_response.status_code})"
            return result
        
        html = page_response.text
        
        # 2. Trouve automatiquement les bundles JS référencés dans le HTML
        bundle_urls = _extract_bundle_urls(html, target_url)
        result["bundles_found"] = bundle_urls
        
        if not bundle_urls:
            result["status"] = "partial"
            result["error"] = "Aucun bundle JavaScript trouvé (cible non-SPA ?)"
            # On analyse quand même le HTML lui-même
            bundle_urls = []
        
        # 3. Télécharge et analyse chaque bundle
        all_js_content = html  # on inclut le HTML aussi
        
        for bundle_url in bundle_urls[:max_bundles]:
            try:
                js_response = requests.get(
                    bundle_url,
                    timeout=timeout,
                    headers=DEFAULT_HEADERS,
                )
                if js_response.status_code == 200:
                    all_js_content += "\n" + js_response.text
                    result["bundles_analyzed"] += 1
            except Exception:
                # Un bundle échoue, on continue avec les autres
                continue
        
        # 4. Extrait les différents types d'informations
        result["api_endpoints"] = _extract_api_endpoints(all_js_content)
        result["app_routes"] = _extract_app_routes(all_js_content)
        result["backend_urls"] = _extract_backend_urls(all_js_content, target_url)
        result["sensitive_keywords"] = _count_sensitive_keywords(all_js_content)
        result["potential_secrets"] = _extract_potential_secrets(all_js_content)
    
    except requests.exceptions.Timeout:
        result["status"] = "error"
        result["error"] = f"Timeout après {timeout}s"
    except requests.exceptions.RequestException as e:
        result["status"] = "error"
        result["error"] = f"Erreur réseau : {type(e).__name__}: {str(e)}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"
    
    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    
    return result


def _extract_bundle_urls(html: str, base_url: str) -> list[str]:
    """
    Extrait les URLs des fichiers JavaScript référencés dans le HTML.
    
    Cherche les balises <script src="..."> et résout les chemins relatifs
    en URLs absolues.
    """
    # Cherche tous les src de balises script pointant vers du .js
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)
    
    # Cherche aussi les modules ES6 (type="module")
    module_srcs = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)
    
    # Combine et déduplique
    all_srcs = set(script_srcs + module_srcs)
    
    # Résout les chemins relatifs en URLs absolues
    absolute_urls = []
    for src in all_srcs:
        absolute_url = urljoin(base_url, src)
        absolute_urls.append(absolute_url)
    
    return sorted(set(absolute_urls))


def _extract_api_endpoints(content: str) -> list[str]:
    """
    Extrait les chemins d'API du contenu JS.
    
    Cherche les patterns de type "/api/...", "/v1/...", "/rest/...".
    Générique : ne suppose aucun préfixe spécifique à une cible.
    """
    patterns = [
        r'["\'`](/api/[a-zA-Z0-9/_{}.$:-]*)["\'`]',
        r'["\'`](/v\d+/[a-zA-Z0-9/_{}.$:-]*)["\'`]',
        r'["\'`](/rest/[a-zA-Z0-9/_{}.$:-]*)["\'`]',
        r'["\'`](/graphql[a-zA-Z0-9/_{}.$:-]*)["\'`]',
    ]
    
    endpoints = set()
    for pattern in patterns:
        for match in re.findall(pattern, content):
            # Nettoie les variables de template JS (ex: /api/users/${id})
            cleaned = re.sub(r'\$\{[^}]*\}', '{param}', match)
            endpoints.add(cleaned)
    
    return sorted(endpoints)


def _extract_app_routes(content: str) -> list[str]:
    """
    Extrait les routes frontend de l'application (pages SPA).
    
    Cherche les chemins courts qui ressemblent à des routes utilisateur
    (ex: /login, /admin, /cart) en excluant les assets.
    """
    # Cherche les chemins courts (routes typiques)
    raw_paths = re.findall(r'["\'`](/[a-zA-Z][a-zA-Z0-9/_-]{1,40})["\'`]', content)
    
    routes = set()
    excluded_extensions = (".js", ".css", ".png", ".svg", ".jpg", ".jpeg",
                           ".ico", ".woff", ".woff2", ".ttf", ".map", ".json")
    excluded_prefixes = ("/assets", "/static", "/node_modules")
    
    for path in raw_paths:
        path_lower = path.lower()
        if path_lower.endswith(excluded_extensions):
            continue
        if any(path_lower.startswith(prefix) for prefix in excluded_prefixes):
            continue
        # Exclut les chemins d'API (déjà capturés ailleurs)
        if path_lower.startswith(("/api/", "/v1/", "/v2/", "/rest/")):
            continue
        routes.add(path)
    
    return sorted(routes)


# Sous-domaines qui désignent typiquement un backend/une instance liée de la
# MÊME organisation (api.cible, dev.cible, staging.cible…).
_BACKEND_SUBDOMAIN_LABELS = frozenset({
    "api", "backend", "back", "rest", "graphql", "gateway", "gw",
    "dev", "staging", "stage", "preprod", "preprod", "test", "qa", "uat",
    "app", "admin", "auth", "account", "accounts", "service", "services",
})

# Domaines tiers récurrents à ignorer même en cas d'homonymie partielle
# (doc de frameworks, standards, CDN, réseaux sociaux…). Filet de sécurité :
# le filtre PRINCIPAL est la contrainte de MÊME domaine racine ci-dessous.
_IGNORE_DOMAINS = (
    "w3.org", "schema.org", "localhost", "example.com", "example.org",
    "reactjs.org", "react.dev", "nextjs.org", "vuejs.org", "angular.io",
    "svelte.dev", "vercel.com", "vercel.app", "netlify.app", "github.com",
    "githubusercontent.com", "gitlab.com", "npmjs.com", "nodejs.org",
    "googleapis.com", "gstatic.com", "google.com", "cloudflare.com",
    "cloudflareinsights.com", "jsdelivr.net", "unpkg.com", "cdnjs.com",
    "jquery.com", "bootstrapcdn.com", "fontawesome.com", "sentry.io",
    "instagram.com", "linkedin.com", "tiktok.com", "facebook.com",
    "twitter.com", "x.com", "youtube.com", "mozilla.org",
)

# Un vrai segment d'API (pas une sous-chaîne : /api-reference ne compte pas).
_API_PATH_RE = re.compile(r'/(?:api|rest|graphql)(?:/|$)|/v\d+(?:/|$)', re.IGNORECASE)


def _looks_like_api(url: str, host: str) -> bool:
    """Signal de backend/API RÉEL : segment /api|/rest|/graphql|/vN, ou sous-domaine dédié."""
    path = urlparse(url).path or ""
    if _API_PATH_RE.search(path):
        return True
    first_label = host.split(".", 1)[0]
    return first_label in _BACKEND_SUBDOMAIN_LABELS


def _extract_backend_urls(content: str, target_url: str) -> list[str]:
    """
    Repère un éventuel backend/instance liée de l'application testée.

    Deux garde-fous, pour ne JAMAIS confondre un lien tiers (doc de framework,
    CDN, réseau social) avec « le backend » — l'erreur qui a fait attaquer
    nextjs.org au lieu de la vraie cible :

      1. MÊME domaine racine que la cible (p. ex. api.cible / dev.cible pour
         cible.tld), via scope_guard.same_site → exclut d'emblée nextjs.org,
         react.dev, github, réseaux sociaux, CDN… (domaines différents) ;
      2. Signal d'API RÉEL : un vrai segment /api|/rest|/graphql|/vN (pas la
         sous-chaîne « /api-reference ») OU un sous-domaine dédié (api., dev.…).

    Les URLs retournées restent des assets à SURFACER : leur éventuel test
    reste soumis au RoE (un sous-domaine ≠ la cible n'est pas attaqué d'office).
    """
    target_host = host_of(target_url)

    all_urls = set(re.findall(r'https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9/_.{}$-]*)?', content))

    backend_urls = set()
    for url in all_urls:
        host = host_of(url)
        if not host or host == target_host:
            continue  # cible elle-même ou URL illisible
        if not same_site(url, target_url):
            continue  # domaine racine DIFFÉRENT → jamais « le backend »
        if any(ig in host for ig in _IGNORE_DOMAINS):
            continue  # filet de sécurité (homonymie improbable mais explicite)
        if _looks_like_api(url, host):
            backend_urls.add(url)

    return sorted(backend_urls)


# Mots-clés sensibles à rechercher (génériques, pas spécifiques à une cible)
SENSITIVE_KEYWORDS = [
    "token", "password", "secret", "apiKey", "api_key", "jwt",
    "bearer", "authorization", "credential", "private_key",
    "access_token", "refresh_token", "client_secret", "admin",
]


def _count_sensitive_keywords(content: str) -> dict[str, int]:
    """Compte les occurrences de mots-clés sensibles dans le contenu."""
    counts = {}
    for kw in SENSITIVE_KEYWORDS:
        count = len(re.findall(re.escape(kw), content, re.IGNORECASE))
        if count > 0:
            counts[kw] = count
    return counts


def _extract_potential_secrets(content: str) -> list[dict[str, str]]:
    """
    Détecte des chaînes ressemblant à des secrets hardcodés.
    
    Cherche des patterns de clés API, tokens JWT, etc. dans le code.
    """
    secrets = []
    
    # JWT (eyJ... format)
    jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
    for match in re.findall(jwt_pattern, content):
        secrets.append({
            "type": "JWT token",
            "value_preview": match[:30] + "...",
        })
    
    # Clés API génériques (assignations type apiKey: "...", key="...")
    apikey_pattern = r'(?:api[_-]?key|secret|token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{16,})["\']'
    for match in re.findall(apikey_pattern, content, re.IGNORECASE):
        # Évite les faux positifs évidents (mots courants)
        if not match.lower() in ("authorization", "content-type"):
            secrets.append({
                "type": "Possible hardcoded key/secret",
                "value_preview": match[:20] + "..." if len(match) > 20 else match,
            })
    
    # Déduplique
    seen = set()
    unique = []
    for s in secrets:
        key = s["value_preview"]
        if key not in seen:
            seen.add(key)
            unique.append(s)
    
    return unique[:20]  # limite à 20
