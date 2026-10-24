"""
Test de la bibliothèque d'évasion WAF (couche PURE, sans réseau ni requests).

Vérifie les transformations de charges (tamper), la génération de variantes et
la détection de blocage WAF — toute la logique testable hors-ligne sur Windows.

Exécution : python test_waf_evasion.py
(ou : pytest test_waf_evasion.py)
"""

from pentagon.tools.waf_evasion_tool import (
    alternate_case,
    space_to_comment,
    intra_keyword_comment,
    equal_to_like,
    url_encode,
    double_url_encode,
    apostrophe_fullwidth,
    mutate,
    generate_sql_variants,
    generate_xss_variants,
    is_waf_blocked,
)


# --- Transformations élémentaires --------------------------------------------

def test_alternate_case():
    assert alternate_case("select") == "SeLeCt"
    # Les non-lettres ne rompent pas l'alternance
    assert alternate_case("a b") == "A b"
    print("✓ test_alternate_case")


def test_space_to_comment():
    assert space_to_comment("' OR 1=1") == "'/**/OR/**/1=1"
    print("✓ test_space_to_comment")


def test_intra_keyword_comment():
    # Un commentaire inline est inséré au milieu de CHAQUE mot-clé SQL, ce qui
    # casse la correspondance de signature mot-à-mot du WAF (le moteur SQL, lui,
    # ignore les commentaires). Le point d'insertion est le milieu du mot-clé :
    # UNION (5) -> « UN/**/ION », SELECT (6) -> « SEL/**/ECT ».
    out = intra_keyword_comment("UNION SELECT")
    assert "/**/" in out
    assert out == "UN/**/ION SEL/**/ECT"
    print("✓ test_intra_keyword_comment")


def test_equal_to_like():
    assert equal_to_like("1=1") == "1 LIKE 1"
    print("✓ test_equal_to_like")


def test_url_and_double_encode():
    assert url_encode("' OR") == "%27%20OR"
    # Le double encodage ré-encode le signe pourcent : %27 -> %2527
    assert double_url_encode("'") == "%2527"
    print("✓ test_url_and_double_encode")


def test_apostrophe_fullwidth():
    out = apostrophe_fullwidth("' OR '1'='1")
    assert "'" not in out
    assert "＇" in out
    print("✓ test_apostrophe_fullwidth")


# --- Composition et génération de variantes ----------------------------------

def test_mutate_chaine():
    # Chaîne : casse puis commentaires
    out = mutate("OR 1=1", ["alternate_case", "space_to_comment"])
    assert "/**/" in out
    # Une technique inconnue est ignorée sans planter
    assert mutate("x", ["inexistante"]) == "x"
    print("✓ test_mutate_chaine")


def test_generate_sql_variants_non_vide_et_dedupe():
    variants = generate_sql_variants("' OR '1'='1' -- ")
    assert len(variants) >= 5
    payloads = [v["payload"] for v in variants]
    # Toutes différentes de l'original et entre elles
    assert "' OR '1'='1' -- " not in payloads
    assert len(payloads) == len(set(payloads))
    # Chaque variante porte un nom de technique
    assert all(v["technique"] for v in variants)
    print("✓ test_generate_sql_variants_non_vide_et_dedupe")


def test_generate_xss_variants():
    variants = generate_xss_variants("<script>alert(1)</script>")
    payloads = [v["payload"] for v in variants]
    assert len(variants) >= 2
    assert "<script>alert(1)</script>" not in payloads
    print("✓ test_generate_xss_variants")


# --- Détection de blocage WAF ------------------------------------------------

def test_is_waf_blocked_cloudflare_403():
    assert is_waf_blocked(
        403,
        {"Server": "cloudflare", "CF-RAY": "abc"},
        "Attention Required! Cloudflare",
    ) is True
    print("✓ test_is_waf_blocked_cloudflare_403")


def test_is_waf_blocked_reponse_appli_normale():
    # 200 applicatif classique → pas un blocage
    assert is_waf_blocked(200, {"Server": "nginx"}, "<html>ok</html>") is False
    # 403 applicatif SANS marqueur WAF → pas un blocage WAF
    assert is_waf_blocked(403, {"Server": "nginx"}, "Forbidden") is False
    print("✓ test_is_waf_blocked_reponse_appli_normale")


def main():
    print("=" * 70)
    print("TEST — Bibliothèque d'évasion WAF (waf_evasion_tool)")
    print("=" * 70)
    test_alternate_case()
    test_space_to_comment()
    test_intra_keyword_comment()
    test_equal_to_like()
    test_url_and_double_encode()
    test_apostrophe_fullwidth()
    test_mutate_chaine()
    test_generate_sql_variants_non_vide_et_dedupe()
    test_generate_xss_variants()
    test_is_waf_blocked_cloudflare_403()
    test_is_waf_blocked_reponse_appli_normale()
    print("=" * 70)
    print("✓ Tous les tests d'évasion WAF passent.")
    print("=" * 70)


if __name__ == "__main__":
    main()
