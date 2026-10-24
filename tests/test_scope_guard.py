"""
Tests PURS de la garde de périmètre (pentagon/core/scope_guard.py).

Couvre la normalisation d'hôte, le domaine enregistrable, same_site et surtout
host_in_scope (deny-by-default), y compris le scénario réel exemple.com /
nextjs.org / dev.exemple.com qui a motivé le correctif. Aucun réseau.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentagon.core.scope_guard import (
    host_of, registrable_domain, same_site, host_in_scope,
)


def test_host_of():
    assert host_of("https://exemple.com/en/") == "exemple.com"
    assert host_of("exemple.com") == "exemple.com"
    assert host_of("https://user:pass@dev.exemple.com:8443/x") == "dev.exemple.com"
    assert host_of("HTTP://Exemple.Com/API") == "exemple.com"
    assert host_of("") == ""
    assert host_of(None) == ""


def test_registrable_domain():
    assert registrable_domain("dev.exemple.com") == "exemple.com"
    assert registrable_domain("api.staging.exemple.com") == "exemple.com"
    assert registrable_domain("exemple.com") == "exemple.com"
    assert registrable_domain("a.b.co.uk") == "b.co.uk"      # eTLD à 2 niveaux
    assert registrable_domain("localhost") == "localhost"
    assert registrable_domain("") == ""


def test_same_site():
    assert same_site("https://dev.exemple.com/x", "https://exemple.com/") is True
    assert same_site("https://api.exemple.com", "exemple.com") is True
    assert same_site("https://nextjs.org/docs", "https://exemple.com") is False
    assert same_site("https://react.dev", "https://exemple.com") is False
    assert same_site("", "https://exemple.com") is False


def test_host_in_scope_same_host_allowed():
    # L'hôte exact de la cible est toujours dans le périmètre.
    assert host_in_scope("https://exemple.com/api/users", "https://exemple.com/") is True
    assert host_in_scope("https://exemple.com/en/", "https://exemple.com") is True


def test_host_in_scope_denies_third_party():
    # LE bug : un lien de doc tiers ne doit JAMAIS être dans le périmètre.
    bad = "https://nextjs.org/docs/app/api-reference/functions/cookies"
    assert host_in_scope(bad, "https://exemple.com/") is False
    assert host_in_scope("https://github.com/x/api", "https://exemple.com/") is False


def test_host_in_scope_subdomain_not_auto_expanded():
    # Un sous-domaine du même domaine racine n'est PAS autorisé d'office :
    # c'est un autre hôte → deny-by-default sans autorisation explicite du RoE.
    assert host_in_scope("https://dev.exemple.com/api", "https://exemple.com/") is False


def test_host_in_scope_respects_roe_authorization():
    # Si le RoE autorise explicitement (scope interactif), alors c'est permis.
    def roe_allows_dev(url):
        return {"allowed": "dev.exemple.com" in url}
    assert host_in_scope("https://dev.exemple.com/api", "https://exemple.com/",
                         scope_check=roe_allows_dev) is True
    assert host_in_scope("https://evil.example/api", "https://exemple.com/",
                         scope_check=roe_allows_dev) is False


def test_host_in_scope_edge_cases():
    assert host_in_scope("", "https://exemple.com/") is False
    # Un scope_check qui lève ne doit jamais ouvrir le périmètre.
    def boom(url):
        raise RuntimeError("x")
    assert host_in_scope("https://x.example", "https://exemple.com/", scope_check=boom) is False


def main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests OK")


if __name__ == "__main__":
    main()
