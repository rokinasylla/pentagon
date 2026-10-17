#!/usr/bin/env python3
"""
Tests PURS des confirmations par catégorie (pentagon/core/confirmation.py) et
de la forge JWT (pentagon/tools/jwt_analyzer_tool.forge_jwt).

Aucun réseau : la forge est pure, et toute I/O passe par un `fetch` INJECTÉ
(faux) qui simule les réponses de la cible. On valide le flux phare JWT
(forge → lecture réelle d'une ressource protégée) et l'IDOR, y compris les cas
de non-confirmation et de refus RoE en amont.
"""

import base64
import hashlib
import hmac
import json

from pentagon.tools.jwt_analyzer_tool import (
    forge_jwt, _decode_jwt_part, _b64url,
)
from pentagon.core.confirmation import (
    jwt_confirmation, idor_confirmation, build_confirmation_actions,
    merge_actions,
)

results = []


def check(name, condition):
    results.append(bool(condition))
    print(f"  {'✓' if condition else '✗ ÉCHEC'} {name}")


def _make_token(header, payload, secret=None):
    h = _b64url(header)
    p = _b64url(payload)
    if secret and header.get("alg", "").upper().startswith("HS"):
        hf = {"HS256": hashlib.sha256}[header["alg"].upper()]
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), f"{h}.{p}".encode(), hf).digest()
        ).rstrip(b"=").decode()
        return f"{h}.{p}.{sig}"
    return f"{h}.{p}."


# ------------------------------- forge_jwt -------------------------------
def test_forge_none_alg():
    print("test_forge_none_alg")
    tok = _make_token({"alg": "none", "typ": "JWT"}, {"sub": "u1", "role": "user"})
    forged = forge_jwt(tok, {"role": "admin"})
    check("forge réussie (alg none)", bool(forged))
    payload = _decode_jwt_part(forged.split(".")[1])
    check("role élevé à admin", payload["role"] == "admin")
    check("autres claims conservés", payload["sub"] == "u1")
    check("signature vide (none)", forged.endswith("."))


def test_forge_hs256_with_secret():
    print("test_forge_hs256_with_secret")
    secret = "secret"
    tok = _make_token({"alg": "HS256", "typ": "JWT"},
                      {"sub": "u1", "role": "user"}, secret=secret)
    forged = forge_jwt(tok, {"sub": "victim", "role": "admin"}, secret=secret)
    check("forge réussie (HS256 + secret)", bool(forged))
    # La signature forgée doit être valide pour le secret.
    h, p, sig = forged.split(".")
    expected = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    check("signature HMAC valide", sig == expected)
    check("claim victime imposé",
          _decode_jwt_part(p)["sub"] == "victim")


def test_forge_hs256_without_secret():
    print("test_forge_hs256_without_secret")
    tok = _make_token({"alg": "HS256"}, {"sub": "u1"}, secret="secret")
    check("forge impossible sans secret",
          forge_jwt(tok, {"role": "admin"}) is None)


def test_forge_rejects_asym_and_malformed():
    print("test_forge_rejects_asym_and_malformed")
    tok = _make_token({"alg": "RS256"}, {"sub": "u1"})
    check("RS256 non forgeable", forge_jwt(tok, {"role": "admin"}) is None)
    check("token malformé -> None", forge_jwt("pasuntoken", {"x": 1}) is None)
    check("une seule partie -> None", forge_jwt("abc", {"x": 1}) is None)


# --------------------------- jwt_confirmation ----------------------------
def _jwt_fetch(responses):
    """Faux fetch : renvoie une réponse selon le token envoyé (forgé vs autre)."""
    seen = []

    def fetch(url, token):
        seen.append((url, token))
        return responses(url, token)
    fetch.seen = seen
    return fetch


def test_jwt_confirm_success():
    print("test_jwt_confirm_success")
    tok = _make_token({"alg": "none"}, {"sub": "u1", "role": "user"})

    def responses(url, token):
        payload = _decode_jwt_part(token.split(".")[1]) if token else {}
        if payload.get("role") == "admin":
            return {"status": 200, "body": "admin dashboard: victim@corp.example"}
        return {"status": 403, "body": "forbidden"}

    fetch = _jwt_fetch(responses)
    action = jwt_confirmation(
        fetch=fetch, token=tok, protected_url="https://v.me/api/admin",
        baseline_status=403, owner_markers=("victim@corp.example",))
    out = action(None, "confirm", None)
    check("confirmé", out["confirmed"] is True)
    check("proven vrai", out["proven"] is True)
    check("snippet mentionne l'accès", "HTTP 200" in out["snippet"])
    check("données d'autrui mentionnées", "autre utilisateur" in out["snippet"])
    check("le forge a bien été envoyé", fetch.seen[0][1].count(".") == 2)


def test_jwt_confirm_access_denied():
    print("test_jwt_confirm_access_denied")
    tok = _make_token({"alg": "none"}, {"role": "user"})
    # La cible refuse même le token forgé (403) -> non confirmé.
    action = jwt_confirmation(
        fetch=lambda u, t: {"status": 403, "body": "nope"},
        token=tok, protected_url="https://v.me/api/admin", baseline_status=403)
    out = action(None, "confirm", None)
    check("non confirmé si accès refusé", out["confirmed"] is False)
    check("reste prouvé", out["proven"] is True)
    check("raison donne le statut", "403" in out["reason"])


def test_jwt_confirm_markers_absent():
    print("test_jwt_confirm_markers_absent")
    tok = _make_token({"alg": "none"}, {"role": "user"})
    # 200 mais SANS le marqueur de données d'autrui -> non confirmé.
    action = jwt_confirmation(
        fetch=lambda u, t: {"status": 200, "body": "page générique"},
        token=tok, protected_url="https://v.me/api/admin",
        baseline_status=403, owner_markers=("victim@corp.example",))
    out = action(None, "confirm", None)
    check("non confirmé si marqueur absent", out["confirmed"] is False)


def test_jwt_confirm_unforgeable():
    print("test_jwt_confirm_unforgeable")
    # HS256 sans secret -> forge impossible -> non confirmé, proven conservé.
    tok = _make_token({"alg": "HS256"}, {"role": "user"}, secret="s")
    calls = []
    action = jwt_confirmation(
        fetch=lambda u, t: calls.append(1) or {"status": 200, "body": "x"},
        token=tok, protected_url="https://v.me/api/admin")  # pas de secret
    out = action(None, "confirm", None)
    check("non confirmé (forge impossible)", out["confirmed"] is False)
    check("aucun fetch tenté", len(calls) == 0)
    check("raison = secret indisponible", "secret" in out["reason"].lower())


def test_jwt_prove_mode():
    print("test_jwt_prove_mode")
    tok = _make_token({"alg": "none"}, {"role": "user"})
    action = jwt_confirmation(fetch=lambda u, t: {"status": 200, "body": ""},
                              token=tok, protected_url="https://v.me/api/admin")
    out = action(None, "prove", None)
    check("prove -> proven", out["proven"] is True)
    check("prove -> pas confirmé", out["confirmed"] is False)


def test_jwt_confirm_fetch_raises():
    print("test_jwt_confirm_fetch_raises")
    tok = _make_token({"alg": "none"}, {"role": "user"})

    def boom(url, token):
        raise ConnectionError("réseau coupé")

    action = jwt_confirmation(fetch=boom, token=tok,
                              protected_url="https://v.me/api/admin")
    out = action(None, "confirm", None)
    check("erreur fetch -> non confirmé (robuste)", out["confirmed"] is False)
    check("toujours prouvé", out["proven"] is True)


# --------------------------- idor_confirmation ---------------------------
def test_idor_confirm_success():
    print("test_idor_confirm_success")
    action = idor_confirmation(
        fetch=lambda u, t: {"status": 200,
                            "body": '{"email":"alice@corp.example"}'},
        token="mon-jeton", victim_url="https://v.me/api/users/42",
        owner_markers=("alice@corp.example",))
    out = action(None, "confirm", None)
    check("confirmé", out["confirmed"] is True)
    check("snippet mentionne la ressource", "users/42" in out["snippet"])


def test_idor_confirm_no_marker():
    print("test_idor_confirm_no_marker")
    action = idor_confirmation(
        fetch=lambda u, t: {"status": 200, "body": "{}"},
        token="x", victim_url="https://v.me/api/users/42",
        owner_markers=("alice@corp.example",))
    out = action(None, "confirm", None)
    check("non confirmé sans marqueur victime", out["confirmed"] is False)


# ----------------------- build + merge des actions -----------------------
def test_build_confirmation_actions():
    print("test_build_confirmation_actions")
    tok = _make_token({"alg": "none"}, {"role": "user"})
    ctx = {
        "fetch": lambda u, t: {"status": 200, "body": "x"},
        "jwt": {"token": tok, "protected_url": "https://v.me/api/admin"},
        "idor": {"token": "x", "victim_url": "https://v.me/api/users/42"},
    }
    actions = build_confirmation_actions(ctx)
    check("jwt câblé", "jwt" in actions and callable(actions["jwt"]))
    check("idor câblé", "idor" in actions and callable(actions["idor"]))
    check("contexte vide -> aucune action", build_confirmation_actions(None) == {})
    check("sans fetch -> aucune action",
          build_confirmation_actions({"jwt": {}}) == {})
    check("jwt incomplet ignoré",
          "jwt" not in build_confirmation_actions(
              {"fetch": ctx["fetch"], "jwt": {"token": tok}}))


def test_merge_actions_priority():
    print("test_merge_actions_priority")
    base = {"ssti": "base_ssti", "jwt": "base_jwt"}
    extra = {"jwt": "confirm_jwt", "idor": "confirm_idor"}
    merged = merge_actions(base, extra)
    check("base conservée", merged["ssti"] == "base_ssti")
    check("extra prioritaire", merged["jwt"] == "confirm_jwt")
    check("extra ajoutée", merged["idor"] == "confirm_idor")


if __name__ == "__main__":
    print("=" * 70)
    print("TESTS PURS — confirmations par catégorie + forge JWT")
    print("=" * 70)
    for t in (test_forge_none_alg, test_forge_hs256_with_secret,
              test_forge_hs256_without_secret, test_forge_rejects_asym_and_malformed,
              test_jwt_confirm_success, test_jwt_confirm_access_denied,
              test_jwt_confirm_markers_absent, test_jwt_confirm_unforgeable,
              test_jwt_prove_mode, test_jwt_confirm_fetch_raises,
              test_idor_confirm_success, test_idor_confirm_no_marker,
              test_build_confirmation_actions, test_merge_actions_priority):
        t()
    print("=" * 70)
    ok, total = sum(results), len(results)
    if ok == total:
        print(f"✅ TOUS LES TESTS PASSENT ({ok}/{total})")
    else:
        print(f"⚠️  {ok}/{total} tests passés — {total - ok} échec(s)")
    print("=" * 70)
