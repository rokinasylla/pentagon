"""
Tests PURS de la détection de backend du js_analyzer (_extract_backend_urls).

Vérifie le correctif : ne plus confondre un lien de doc de framework
(nextjs.org/.../api-reference) avec « le backend », et ne retenir qu'un backend
du MÊME domaine racine présentant un signal d'API réel. Aucun réseau (l'import
de `requests` est différé, le module s'importe donc hors-ligne).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pentagon.tools.js_analyzer_tool import _extract_backend_urls

TARGET = "https://exemple.com/"


def test_framework_doc_url_is_not_a_backend():
    # Le cas réel : un lien de doc Next.js ne doit PAS devenir le backend,
    # même si "/api-reference" contient la sous-chaîne "/api".
    content = 'var x="https://nextjs.org/docs/app/api-reference/functions/cookies";'
    assert _extract_backend_urls(content, TARGET) == []


def test_same_site_api_subdomain_is_detected():
    content = 'fetch("https://api.exemple.com/v1/users");'
    out = _extract_backend_urls(content, TARGET)
    assert "https://api.exemple.com/v1/users" in out


def test_same_site_dev_subdomain_is_detected():
    # dev.exemple.com = asset lié à surfacer (sous-domaine dédié).
    content = 'const base="https://dev.exemple.com/api/health";'
    out = _extract_backend_urls(content, TARGET)
    assert "https://dev.exemple.com/api/health" in out


def test_third_party_api_paths_excluded():
    # Même avec un vrai /api/, un domaine racine DIFFÉRENT est exclu.
    content = ('"https://github.com/org/api/v2" '
               '"https://react.dev/learn" '
               '"https://www.instagram.com/compte"')
    assert _extract_backend_urls(content, TARGET) == []


def test_target_host_itself_excluded():
    # Une URL same-host est gérée par l'extraction de chemins /api, pas ici.
    content = '"https://exemple.com/api/public"'
    assert _extract_backend_urls(content, TARGET) == []


def test_api_reference_substring_not_matched():
    # Garantit qu'on matche un SEGMENT /api, pas la sous-chaîne.
    content = '"https://docs.exemple.com/api-reference/intro"'  # même site mais pas d'API réelle
    # "api-reference" n'est pas un segment /api ; "docs" n'est pas un sous-domaine backend.
    assert _extract_backend_urls(content, TARGET) == []


def test_mixed_bundle_keeps_only_real_same_site_backend():
    content = (
        '"https://nextjs.org/docs/app/api-reference/functions/cookies" '
        '"https://react.dev/" '
        '"https://www.w3.org/2000/svg" '
        '"https://api.exemple.com/api/login" '
        '"https://github.com/x/api"'
    )
    out = _extract_backend_urls(content, TARGET)
    assert out == ["https://api.exemple.com/api/login"]


def main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests OK")


if __name__ == "__main__":
    main()
