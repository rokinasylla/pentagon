"""
Test de la couche PURE du crawler/fuzzer dynamique (sans navigateur ni réseau).

Vérifie toute la logique testable hors-ligne : extraction de liens et de
formulaires, filtrage de périmètre (deny-by-default), déduplication d'URL,
construction des URLs de fuzzing et classification des réponses.

Exécution : python test_dynamic_crawler.py  (ou : pytest test_dynamic_crawler.py)
"""

from pentagon.tools.dynamic_crawler_tool import (
    normalize_url,
    extract_links,
    extract_forms,
    is_asset,
    in_scope_links,
    build_fuzz_urls,
    classify_fuzz_response,
    FUZZ_XSS_MARKER,
)


# --- normalize_url -----------------------------------------------------------

def test_normalize_url():
    assert normalize_url("https://Exemple.com/A/") == "https://exemple.com/A"
    assert normalize_url("https://exemple.com/a#section") == "https://exemple.com/a"
    assert normalize_url("https://exemple.com/") == "https://exemple.com/"
    assert normalize_url("https://exemple.com/p?b=2&a=1") == "https://exemple.com/p?b=2&a=1"
    assert normalize_url("") == ""
    print("✓ test_normalize_url")


# --- extract_links -----------------------------------------------------------

def test_extract_links_absolu_et_filtre():
    html = """
      <a href="/login">Login</a>
      <a href='produits/42'>Produit</a>
      <a href="https://exemple.com/a">Abs</a>
      <a href="mailto:x@y.z">Mail</a>
      <a href="javascript:void(0)">JS</a>
      <a href="#top">Ancre</a>
      <a href="/login#form">Login again</a>
    """
    links = extract_links(html, "https://exemple.com/")
    assert "https://exemple.com/login" in links
    assert "https://exemple.com/produits/42" in links
    assert "https://exemple.com/a" in links
    # mailto / javascript / ancre pure sont écartés
    assert not any(l.startswith("mailto:") or l.startswith("javascript:") for l in links)
    # le fragment est retiré → /login dédupliqué (une seule occurrence)
    assert links.count("https://exemple.com/login") == 1
    print("✓ test_extract_links_absolu_et_filtre")


# --- extract_forms -----------------------------------------------------------

def test_extract_forms():
    html = """
      <form action="/api/login" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit" value="Go">
      </form>
      <form>
        <input name="q">
        <textarea name="comment"></textarea>
      </form>
    """
    forms = extract_forms(html, "https://exemple.com/page")
    assert len(forms) == 2
    f1 = forms[0]
    assert f1["action"] == "https://exemple.com/api/login"
    assert f1["method"] == "POST"
    names = {i["name"] for i in f1["inputs"]}
    # Le bouton submit n'a pas d'attribut name → correctement ignoré.
    assert names == {"username", "password"}
    # 2e formulaire : pas d'action → hérite de base_url ; méthode défaut GET
    f2 = forms[1]
    assert f2["method"] == "GET"
    assert f2["action"] == "https://exemple.com/page"
    types = {i["name"]: i["type"] for i in f2["inputs"]}
    assert types.get("comment") == "textarea"
    print("✓ test_extract_forms")


# --- is_asset ----------------------------------------------------------------

def test_is_asset():
    assert is_asset("https://exemple.com/static/app.js") is True
    assert is_asset("https://exemple.com/img/logo.PNG") is True
    assert is_asset("https://exemple.com/login") is False
    print("✓ test_is_asset")


# --- in_scope_links (deny-by-default) ----------------------------------------

def test_in_scope_links_deny_by_default():
    target = "https://exemple.com/"
    links = [
        "https://exemple.com/login",         # même hôte → autorisé
        "https://exemple.com/static/app.js",  # asset → écarté
        "https://evil.com/steal",             # tiers → refusé
        "https://dev.exemple.com/panel",      # sous-domaine → refusé d'office
    ]
    kept = in_scope_links(links, target)
    assert kept == ["https://exemple.com/login"]

    # Avec un RoE qui autorise explicitement le sous-domaine dev → il passe.
    allow_dev = lambda u: {"allowed": "dev.exemple.com" in u}
    kept2 = in_scope_links(links, target, scope_check=allow_dev)
    assert "https://dev.exemple.com/panel" in kept2
    assert "https://evil.com/steal" not in kept2
    print("✓ test_in_scope_links_deny_by_default")


# --- build_fuzz_urls ---------------------------------------------------------

def test_build_fuzz_urls():
    # URL avec paramètres : chaque paramètre muté tour à tour
    urls = build_fuzz_urls("https://exemple.com/s?a=1&b=2", "PAY")
    assert any("a=PAY" in u and "b=2" in u for u in urls)
    assert any("b=PAY" in u and "a=1" in u for u in urls)
    assert len(urls) == 2
    # URL sans paramètre : injection sur des noms courants
    urls2 = build_fuzz_urls("https://exemple.com/search", "PAY")
    assert any("q=PAY" in u for u in urls2)
    assert build_fuzz_urls("", "PAY") == []
    print("✓ test_build_fuzz_urls")


# --- classify_fuzz_response --------------------------------------------------

def test_classify_fuzz_response():
    # Exécution XSS = signal le plus fort (priorité)
    v = classify_fuzz_response(200, "<html>ok</html>", "x", xss_executed=True)
    assert v["signal"] == "xss_exec" and v["severity"] == "high"

    # Erreur SQL dans le corps
    v = classify_fuzz_response(200, "You have an error in your SQL syntax near", "'")
    assert v["signal"] == "sql_error"

    # Réflexion telle quelle de la charge
    pay = '<img src=x onerror=1>'
    v = classify_fuzz_response(200, f"<div>{pay}</div>", pay)
    assert v["signal"] == "reflection" and v["severity"] == "medium"

    # Erreur serveur déclenchée
    v = classify_fuzz_response(500, "Internal Server Error", "%")
    assert v["signal"] == "server_error"

    # Réponse normale → aucun signal
    v = classify_fuzz_response(200, "<html>bienvenue</html>", "'")
    assert v["signal"] is None
    print("✓ test_classify_fuzz_response")


def test_classify_baseline_anti_faux_positif():
    # Une signature SQL DÉJÀ présente dans la réponse normale (baseline) ne doit
    # PAS être comptée : seul ce que la charge INTRODUIT compte.
    page_with_sig = "<html>... postgresql driver docs ...</html>"
    v = classify_fuzz_response(200, page_with_sig, "'", baseline_body=page_with_sig)
    assert v["signal"] is None  # présente des deux côtés → pas un signal

    # La même signature apparaissant SEULEMENT avec la charge → vrai signal.
    clean = "<html>bienvenue</html>"
    errored = "<html>you have an error in your SQL syntax</html>"
    v = classify_fuzz_response(200, errored, "'", baseline_body=clean)
    assert v["signal"] == "sql_error"
    print("✓ test_classify_baseline_anti_faux_positif")


def test_marker_present():
    # Le marqueur XSS de fuzzing est bien défini et inerte (juste un nom window).
    assert FUZZ_XSS_MARKER and FUZZ_XSS_MARKER.isidentifier()
    print("✓ test_marker_present")


def main():
    print("=" * 70)
    print("TEST — Crawler/fuzzer dynamique (couche PURE)")
    print("=" * 70)
    test_normalize_url()
    test_extract_links_absolu_et_filtre()
    test_extract_forms()
    test_is_asset()
    test_in_scope_links_deny_by_default()
    test_build_fuzz_urls()
    test_classify_fuzz_response()
    test_classify_baseline_anti_faux_positif()
    test_marker_present()
    print("=" * 70)
    print("✓ Tous les tests du crawler/fuzzer dynamique passent.")
    print("=" * 70)


if __name__ == "__main__":
    main()
