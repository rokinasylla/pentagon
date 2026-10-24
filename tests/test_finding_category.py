"""
Tests PURS de la classification des findings et de la notion d'exploitabilité
(pentagon/core/finding.py).

Couvre le correctif UX : les failles d'OBSERVATION (divulgation d'en-tête,
en-têtes de sécurité, TLS, CVE, config) reçoivent désormais une catégorie
NON VIDE et sont marquées non exploitables → l'UI ne propose plus « /exploit »
à tort, et le message n'est plus « catégorie '' ». Aucun réseau.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentagon.core.finding import (
    infer_category, is_exploitable_category, Finding,
    EXPLOITABLE_CATEGORIES, OBSERVATION_CATEGORIES,
)


def test_infer_classifies_observation_findings():
    # LE cas du screenshot : plus jamais de catégorie vide.
    assert infer_category("Divulgation d'information via le header Server") == "info_disclosure"
    assert infer_category("En-têtes de sécurité manquants (CSP, HSTS)") == "security_headers"
    assert infer_category("Certificat TLS expiré / chiffrement faible") == "tls"
    assert infer_category("CVE-2021-41773 sur le composant Apache") == "cve"
    assert infer_category("Méthode HTTP TRACE activée") == "misconfig"


def test_infer_still_classifies_exploitable():
    assert infer_category("Injection SQL sur le login") == "sqli"
    assert infer_category("XSS réfléchi sur le paramètre q") == "xss"
    assert infer_category("Traversée de répertoire / LFI") == "lfi"
    assert infer_category("JWT à secret faible") == "jwt"


def test_infer_by_cwe():
    assert infer_category(cwe="CWE-200") == "info_disclosure"
    assert infer_category(cwe="89") == "sqli"
    assert infer_category(cwe="CWE-79") == "xss"


def test_unknown_stays_empty():
    assert infer_category("Quelque chose d'inclassable zzz") == ""


def test_is_exploitable_category():
    assert is_exploitable_category("sqli") is True
    assert is_exploitable_category("lfi") is True
    assert is_exploitable_category("info_disclosure") is False
    assert is_exploitable_category("security_headers") is False
    assert is_exploitable_category("tls") is False
    assert is_exploitable_category("") is False          # catégorie vide = non exploitable
    assert is_exploitable_category("inconnue") is False


def test_categories_are_disjoint():
    assert EXPLOITABLE_CATEGORIES.isdisjoint(OBSERVATION_CATEGORIES)


def test_finding_exploitable_flag_and_to_dict():
    f_obs = Finding(session_id="s", title="Divulgation header Server", category="info_disclosure")
    assert f_obs.exploitable is False
    assert f_obs.to_dict()["exploitable"] is False

    f_sqli = Finding(session_id="s", title="SQLi login", category="sqli")
    assert f_sqli.exploitable is True
    assert f_sqli.to_dict()["exploitable"] is True


def main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} tests OK")


if __name__ == "__main__":
    main()
