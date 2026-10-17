"""
Confirmations par catégorie pour l'exploitation à la demande (Lot UI-2).

`exploit(finding, mode="confirm")` pousse la démonstration d'un cran : prouver
qu'une faille a un IMPACT RÉEL, pas seulement qu'elle existe. Ce module fournit
les STRATÉGIES de confirmation par catégorie, sous la forme d'« actions »
(contrat {tool, proven, confirmed, snippet, reason}) que l'agent Exploitation
sait consommer via son registre injectable.

Exemple phare — JWT : la campagne a prouvé qu'un token est FORGEABLE (algo
'none' ou secret faible cracké). La confirmation FORGE un token élevant les
privilèges (role=admin, ou l'identité d'un autre utilisateur) et s'en sert pour
LIRE une ressource protégée que le token d'origine ne pouvait pas atteindre —
démontrant l'élévation de privilèges / l'accès aux données d'autrui.

Garde-fous :
  - DÉTECTER EN PROUVANT, JAMAIS RAVAGER : la confirmation est en LECTURE SEULE
    (GET), jamais d'écriture ni d'exfiltration. On montre l'accès, on ne
    l'exploite pas au-delà.
  - PUR / INJECTABLE : la forge est pure (jwt_analyzer.forge_jwt) et toute I/O
    réseau passe par un `fetch` INJECTÉ — ce module se teste hors ligne. La
    requête réelle (et la garde RoE) restent portées par l'appelant.

Contrat du `fetch` injecté :
    fetch(url: str, token: str | None) -> {"status": int, "body": str}
"""

from __future__ import annotations

from typing import Any, Callable

from pentagon.tools.jwt_analyzer_tool import forge_jwt

# Statuts qui signalent un refus d'accès (baseline « normale » avant forge).
_DENIED_STATUSES = (401, 403)

FetchFn = Callable[[str, "str | None"], dict]


def _safe_fetch(fetch: FetchFn, url: str, token: str | None) -> dict[str, Any]:
    """Appelle le fetch injecté en absorbant toute erreur (→ statut 0)."""
    try:
        resp = fetch(url, token) or {}
        return {"status": int(resp.get("status") or 0),
                "body": str(resp.get("body") or "")}
    except Exception as e:  # pas de réseau dans les tests, robustesse en prod
        return {"status": 0, "body": "", "error": f"{type(e).__name__}: {e}"}


def jwt_confirmation(
    *,
    fetch: FetchFn,
    token: str,
    protected_url: str,
    secret: str | None = None,
    elevate: dict[str, Any] | None = None,
    baseline_status: int | None = None,
    owner_markers: tuple[str, ...] = (),
) -> Callable:
    """
    Stratégie de confirmation JWT : forge un token à privilèges élevés et
    l'utilise pour lire une ressource protégée (lecture seule).

    Args:
        fetch: I/O réseau injectée (GET avec le token en Authorization).
        token: le token d'origine (forgeable) à partir duquel forger.
        protected_url: ressource protégée à lire avec le token forgé.
        secret: secret HMAC cracké (requis pour forger un HS*, inutile pour 'none').
        elevate: claims à imposer (défaut {"role": "admin"}).
        baseline_status: statut obtenu SANS privilège (ex. 401/403) — sert à
            prouver que le forge a bien DÉBLOQUÉ l'accès.
        owner_markers: fragments attestant la présence de données d'AUTRUI dans
            la réponse (ex. e-mail d'un autre compte). Si fournis, ils doivent
            apparaître pour confirmer l'accès effectif aux données.
    """
    overrides = elevate or {"role": "admin"}

    def action(finding: Any, mode: str, tok: str | None) -> dict[str, Any]:
        if mode != "confirm":
            # La forgeabilité est déjà prouvée par la campagne.
            return {"tool": "jwt_forge", "proven": True, "confirmed": False,
                    "snippet": "Token JWT forgeable (prouvé par l'analyse).",
                    "reason": ""}

        forged = forge_jwt(token, overrides, secret=secret)
        if not forged:
            return {"tool": "jwt_forge", "proven": True, "confirmed": False,
                    "reason": "Forge impossible (algorithme asymétrique ou "
                              "secret indisponible)."}

        resp = _safe_fetch(fetch, protected_url, forged)
        status, body = resp["status"], resp["body"]

        baseline_denied = (baseline_status in _DENIED_STATUSES
                           or baseline_status is None)
        access_granted = status == 200 and baseline_denied
        if owner_markers:
            foreign = any(m in body for m in owner_markers)
        else:
            foreign = access_granted  # pas de marqueur fourni : l'accès suffit

        confirmed = bool(access_granted and foreign)
        if confirmed:
            label = ", ".join(f"{k}={v}" for k, v in overrides.items())
            snippet = (f"Token forgé ({label}) accepté : HTTP {status} sur "
                       f"{protected_url}"
                       + (" — données d'un autre utilisateur lues"
                          if owner_markers else ""))
            return {"tool": "jwt_forge", "proven": True, "confirmed": True,
                    "snippet": snippet, "reason": ""}
        return {"tool": "jwt_forge", "proven": True, "confirmed": False,
                "reason": f"Token forgé envoyé mais accès non obtenu "
                          f"(HTTP {status})."}

    return action


def idor_confirmation(
    *,
    fetch: FetchFn,
    token: str | None,
    victim_url: str,
    owner_markers: tuple[str, ...] = (),
) -> Callable:
    """
    Stratégie de confirmation IDOR : lit la ressource d'un AUTRE utilisateur et
    atteste la présence de ses données (lecture seule).

    `owner_markers` = fragments appartenant à la victime (e-mail, nom…) dont la
    présence prouve l'accès horizontal effectif.
    """
    def action(finding: Any, mode: str, tok: str | None) -> dict[str, Any]:
        if mode != "confirm":
            return {"tool": "idor_fetch", "proven": True, "confirmed": False,
                    "snippet": "Accès horizontal prouvé par la campagne.",
                    "reason": ""}

        resp = _safe_fetch(fetch, victim_url, token)
        status, body = resp["status"], resp["body"]
        foreign = any(m in body for m in owner_markers) if owner_markers else \
            status == 200
        confirmed = bool(status == 200 and foreign)
        if confirmed:
            return {"tool": "idor_fetch", "proven": True, "confirmed": True,
                    "snippet": f"Ressource d'autrui lue : HTTP {status} sur "
                               f"{victim_url} (données de la victime présentes).",
                    "reason": ""}
        return {"tool": "idor_fetch", "proven": True, "confirmed": False,
                "reason": f"Lecture de la ressource d'autrui non confirmée "
                          f"(HTTP {status})."}

    return action


def build_confirmation_actions(context: dict[str, Any] | None) -> dict[str, Callable]:
    """
    Construit le registre {catégorie: action de confirmation} depuis un contexte
    (issu des données brutes de campagne). N'ajoute une stratégie que si le
    contexte nécessaire est présent — sinon la catégorie reste non confirmable
    (l'exploit retombera sur la preuve standard ou « non pris en charge »).

    `context` attendu :
        {"fetch": FetchFn,
         "jwt":  {token, protected_url, secret?, elevate?, baseline_status?, owner_markers?},
         "idor": {token?, victim_url, owner_markers?}}
    """
    if not context:
        return {}
    fetch = context.get("fetch")
    if not callable(fetch):
        return {}

    actions: dict[str, Callable] = {}
    jwt_ctx = context.get("jwt")
    if isinstance(jwt_ctx, dict) and jwt_ctx.get("token") and jwt_ctx.get("protected_url"):
        actions["jwt"] = jwt_confirmation(
            fetch=fetch,
            token=jwt_ctx["token"],
            protected_url=jwt_ctx["protected_url"],
            secret=jwt_ctx.get("secret"),
            elevate=jwt_ctx.get("elevate"),
            baseline_status=jwt_ctx.get("baseline_status"),
            owner_markers=tuple(jwt_ctx.get("owner_markers") or ()),
        )
    idor_ctx = context.get("idor")
    if isinstance(idor_ctx, dict) and idor_ctx.get("victim_url"):
        actions["idor"] = idor_confirmation(
            fetch=fetch,
            token=idor_ctx.get("token"),
            victim_url=idor_ctx["victim_url"],
            owner_markers=tuple(idor_ctx.get("owner_markers") or ()),
        )
    return actions


def merge_actions(base: dict[str, Callable],
                  extra: dict[str, Callable]) -> dict[str, Callable]:
    """Fusionne deux registres d'actions ; `extra` a priorité par catégorie."""
    merged = dict(base or {})
    merged.update(extra or {})
    return merged
