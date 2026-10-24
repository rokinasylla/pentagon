"""
Tests PURS de la garde de périmètre (pentagon/core/scope_guard.py).

Couvre la normalisation d'hôte, le domaine enregistrable, same_site et surtout
host_in_scope (deny-by-default), y compris le scénario réel nafar.tech /
nextjs.org / dev.nafar.tech qui a motivé le correctif. Aucun réseau.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentagon.core.scope_guard import (
    host_of, registrable_domain, same_site, host_in_scope,
)


def test_host_of():
    assert host_of("https://nafar.tech/en/") == "nafar.tech"
    assert host_of("nafar.tech") == "nafar.tech"
    assert host_of("https://user:pass@dev.nafar.tech:8443/x") == "dev.nafar.tech"
    assert host_of("HTTP://Nafar.Tech/API") == "nafar.tech"
    assert host_of("") == ""
    assert host_of(None) == ""


def test_registrable_domain():
    assert registrable_domain("dev.nafar.tech") == "nafar.tech"
    assert registrable_domain("api.staging.nafar.tech") == "nafar.tech"
    assert registrable_domain("nafar.tech") == "nafar.tech"
    assert registrable_domain("a.b.co.uk") == "b.co.uk"      # eTLD à 2 niveaux
    assert registrable_domain("localhost") == "localhost"
    assert registrable_domain("") == ""


def test_same_site():
    assert same_site("https://dev.nafar.tech/x", "https://nafar.tech/") is True
    assert same_site("https://api.nafar.tech", "nafar.tech") is True
    assert same_site("https://nextjs.org/docs", "https://nafar.tech") is False
    assert same_site("https://react.dev", "https://nafar.tech") is False
    assert same_site("", "https://nafar.tech") is False


def test_host_in_scope_same_host_allowed():
    # L'hôte exact de la cible est toujours dans le périmètre.
    assert host_in_scope("https://nafar.tech/api/users", "https://nafar.tech/") is True
    assert host_in_scope("https://nafar.tech/en/", "https://nafar.tech") is True


def test_host_in_scope_denies_third_party():
    # LE bug : un lien de doc tiers ne doit JAMAIS être dans le périmètre.
    bad = "https://nextjs.org/docs/app/api-reference/functions/cookies"
    assert host_in_scope(bad, "https://nafar.tech/") is False
    assert host_in_scope("https://github.com/x/api", "https://nafar.tech/") is False


def test_host_in_scope_subdomain_not_auto_expanded():
    # Un sous-domaine du même domaine racine n'est PAS autorisé d'office :
    # c'est un autre hôte → deny-by-default sans autorisation explicite du RoE.
    assert host_in_scope("https://dev.nafar.tech/api", "https://nafar.tech/") is False


def test_host_in_scope_respects_roe_authorization():
    # Si le RoE autorise explicitement (scope interactif), alors c'est permis.
    def roe_allows_dev(url):
        return {"allowed": "dev.nafar.tech" in url}
    assert host_in_scope("https://dev.nafar.tech/api", "https://nafar.tech/",
                         scope_check=roe_allows_dev) is True
    assert host_in_scope("https://evil.example/api", "https://nafar.tech/",
                         scope_check=roe_allows_dev) is False


def test_host_in_scope_edge_cases():
    assert host_in_scope("", "https://nafar.tech/") is False
    # Un scope_check qui lève ne doit jamais ouvrir le périmètre.
    def boom(url):
        raise RuntimeError("x")
    assert host_in_scope("https://x.example", "https://nafar.tech/", scope_check=boom) is False


def main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests OK")


if __name__ == "__main__":
    main()
