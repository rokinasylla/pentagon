"""
Test du module Cloudflare (couches PURES, sans réseau).

Vérifie la logique testable hors-ligne des deux outils :
- waf_detector_tool.analyze_waf_signals : détection de WAF/CDN à partir de
  signaux HTTP fournis (en-têtes, code, corps, cookies).
- origin_discovery_tool : is_cloudflare_ip / classify_ips (classification des
  IP par plages Cloudflare) et compare_responses (décision « même appli »).

Exécution : python test_cloudflare_module.py
(ou : pytest test_cloudflare_module.py)
"""

from pentagon.tools.waf_detector_tool import analyze_waf_signals
from pentagon.tools.origin_discovery_tool import (
    is_cloudflare_ip,
    classify_ips,
    compare_responses,
)


# --- Détection WAF -----------------------------------------------------------

def test_cloudflare_detecte_via_headers():
    signals = analyze_waf_signals(
        headers={"Server": "cloudflare", "CF-RAY": "8a1b2c3d4e5f6789-CDG"},
        status_code=200,
        body_snippet="<html><title>TechShop</title></html>",
    )
    assert signals["waf_detected"] is True
    assert signals["is_cloudflare"] is True
    assert signals["vendors"][0] == "Cloudflare"
    assert signals["blocking"] is False
    print("✓ test_cloudflare_detecte_via_headers")


def test_cloudflare_blocage_challenge():
    signals = analyze_waf_signals(
        headers={"Server": "cloudflare", "cf-mitigated": "challenge"},
        status_code=403,
        body_snippet="Attention Required! Cloudflare cf-chl challenge-platform",
        cookies=["__cf_bm", "cf_clearance"],
    )
    assert signals["is_cloudflare"] is True
    assert signals["blocking"] is True
    print("✓ test_cloudflare_blocage_challenge")


def test_aucun_waf_sur_serveur_nu():
    signals = analyze_waf_signals(
        headers={"Server": "nginx/1.24.0", "X-Powered-By": "Express"},
        status_code=200,
        body_snippet="<html><title>Direct origin</title></html>",
    )
    assert signals["waf_detected"] is False
    assert signals["vendors"] == []
    assert signals["is_cloudflare"] is False
    print("✓ test_aucun_waf_sur_serveur_nu")


def test_autre_waf_non_cloudflare():
    signals = analyze_waf_signals(
        headers={"Server": "AkamaiGHost", "X-Akamai-Transformed": "9"},
        status_code=200,
        body_snippet="",
    )
    assert signals["waf_detected"] is True
    assert signals["is_cloudflare"] is False
    assert "Akamai" in signals["vendors"]
    print("✓ test_autre_waf_non_cloudflare")


# --- Classification des IP ---------------------------------------------------

def test_is_cloudflare_ip():
    # 104.16.0.0/13 → une IP de bordure Cloudflare
    assert is_cloudflare_ip("104.16.132.229") is True
    assert is_cloudflare_ip("172.64.5.1") is True
    # Une IP publique quelconque hors plages Cloudflare
    assert is_cloudflare_ip("216.24.57.1") is False
    # Entrées invalides → False (pas de fausse classification)
    assert is_cloudflare_ip("pas-une-ip") is False
    assert is_cloudflare_ip("") is False
    print("✓ test_is_cloudflare_ip")


def test_classify_ips_repartit_et_dedupe():
    result = classify_ips([
        "104.16.132.229",   # Cloudflare
        "104.16.132.229",   # doublon → ignoré
        "216.24.57.1",      # hors Cloudflare (origine candidate)
        "10.0.0.5",         # valide, privée, hors Cloudflare
        "not.an.ip",        # invalide
    ])
    assert result["cloudflare"] == ["104.16.132.229"]
    assert result["non_cloudflare"] == ["216.24.57.1", "10.0.0.5"]
    assert result["invalid"] == ["not.an.ip"]
    print("✓ test_classify_ips_repartit_et_dedupe")


# --- Comparaison de réponses (origine exposée ?) -----------------------------

def test_compare_responses_meme_appli():
    front = {"status": 200, "title": "TechShop", "server": "cloudflare",
             "body_len": 10000, "body_snippet": "cloudflare edge"}
    origin = {"status": 200, "title": "TechShop", "server": "nginx",
              "body_len": 10100, "body_snippet": "<html>TechShop</html>"}
    verdict = compare_responses(front, origin)
    assert verdict["same_app"] is True
    assert verdict["confidence"] >= 0.6
    print("✓ test_compare_responses_meme_appli")


def test_compare_responses_origine_encore_cloudflare():
    # L'IP directe renvoie encore une page Cloudflare → PAS une origine exposée.
    front = {"status": 200, "title": "TechShop", "server": "cloudflare",
             "body_len": 10000, "body_snippet": "cloudflare"}
    origin = {"status": 403, "title": "Attention Required", "server": "cloudflare",
              "body_len": 2000, "body_snippet": "Attention Required! Cloudflare cf-ray"}
    verdict = compare_responses(front, origin)
    assert verdict["same_app"] is False
    print("✓ test_compare_responses_origine_encore_cloudflare")


def test_compare_responses_appli_differente():
    front = {"status": 200, "title": "TechShop", "server": "cloudflare",
             "body_len": 10000, "body_snippet": ""}
    origin = {"status": 404, "title": "Default Web Page", "server": "Apache",
              "body_len": 300, "body_snippet": "It works!"}
    verdict = compare_responses(front, origin)
    assert verdict["same_app"] is False
    print("✓ test_compare_responses_appli_differente")


def main():
    print("=" * 70)
    print("TEST — Module Cloudflare (WAF detection + origin discovery)")
    print("=" * 70)
    test_cloudflare_detecte_via_headers()
    test_cloudflare_blocage_challenge()
    test_aucun_waf_sur_serveur_nu()
    test_autre_waf_non_cloudflare()
    test_is_cloudflare_ip()
    test_classify_ips_repartit_et_dedupe()
    test_compare_responses_meme_appli()
    test_compare_responses_origine_encore_cloudflare()
    test_compare_responses_appli_differente()
    print("=" * 70)
    print("✓ Tous les tests du module Cloudflare passent.")
    print("=" * 70)


if __name__ == "__main__":
    main()
