"""
Outil d'évasion de WAF (mutation de charges) pour PENTAGON.

PROBLÈME RÉSOLU — les faux négatifs derrière un WAF.
Quand un pare-feu applicatif (Cloudflare, etc.) filtre par signatures, il bloque
une charge de test « brute » (SQLi/XSS) avec un 403 avant qu'elle n'atteigne
l'application. Le pentester ne sait alors PAS distinguer :
  - « l'application est sûre » (vrai négatif), de
  - « le WAF a masqué une faille réelle » (faux négatif).

Cet outil applique des transformations d'évasion CONNUES (équivalentes aux
« tamper scripts » de sqlmap : encodages alternatifs, casse, commentaires
inline, fragmentation) pour faire passer la charge devant les signatures et
tester l'application ELLE-MÊME. On mesure alors « bloqué brut → passé après
évasion → l'appli est-elle réellement vulnérable ? ». C'est un gain direct de
qualité du rapport, PAS un outil d'attaque autonome.

GOUVERNANCE — ce module ne fait que transformer des chaînes (aucune I/O réseau).
Son USAGE (envoyer une charge à une cible) reste soumis au RoE : catégorie
`exploitation` + cible autorisée. La gouvernance vit chez l'appelant
(agent Exploitation / orchestrateur), jamais ici.

Standards : OWASP WSTG-INPV (Input Validation), MITRE ATT&CK T1027
(Obfuscated Files or Information), T1190.
"""

from typing import Any, Callable
from urllib.parse import quote


# Codes HTTP typiques d'un blocage/challenge WAF.
_CHALLENGE_STATUS_CODES = {403, 406, 429, 503}

# Mots-clés SQL sur lesquels on insère des commentaires inline.
_SQL_KEYWORDS = [
    "UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP",
    "INSERT", "UPDATE", "DELETE", "HAVING", "LIMIT",
]


# =============================================================================
# Transformations élémentaires (PURES, déterministes → testables hors-ligne)
# Chacune : (payload: str) -> str
# =============================================================================

def alternate_case(payload: str) -> str:
    """Alterne la casse caractère par caractère : « select » -> « SeLeCt ».

    Beaucoup de signatures WAF ciblent des mots-clés en casse fixe ; le moteur
    SQL, lui, est insensible à la casse.
    """
    out = []
    upper = True
    for ch in payload:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return "".join(out)


def space_to_comment(payload: str) -> str:
    """Remplace les espaces par des commentaires SQL vides : « /**/ »."""
    return payload.replace(" ", "/**/")


def space_to_plus(payload: str) -> str:
    """Remplace les espaces par « + » (équivalent espace en query string)."""
    return payload.replace(" ", "+")


def intra_keyword_comment(payload: str) -> str:
    """Insère un commentaire inline dans les mots-clés SQL : « SELECT » ->
    « SE/**/LECT ». Casse la correspondance de signature mot-à-mot.
    """
    result = payload
    for kw in _SQL_KEYWORDS:
        for variant in (kw, kw.lower(), kw.capitalize()):
            if variant in result:
                mid = len(variant) // 2
                injected = variant[:mid] + "/**/" + variant[mid:]
                result = result.replace(variant, injected)
    return result


def equal_to_like(payload: str) -> str:
    """Remplace « = » par « LIKE » (sémantiquement proche en SQL)."""
    return payload.replace("=", " LIKE ")


def url_encode(payload: str) -> str:
    """Encode tous les caractères en pourcent (%27, %20, ...)."""
    return quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    """Double encodage pourcent : « ' » -> « %2527 ». Efficace quand un
    proxy décode une fois avant l'application.
    """
    return quote(quote(payload, safe=""), safe="")


def apostrophe_fullwidth(payload: str) -> str:
    """Remplace l'apostrophe ASCII par son homoglyphe pleine chasse U+FF07,
    parfois normalisé en « ' » côté application mais invisible aux signatures.
    """
    return payload.replace("'", "＇")


# Registre nom -> fonction, pour composer des chaînes de transformations.
TAMPER_TECHNIQUES: dict[str, Callable[[str], str]] = {
    "alternate_case": alternate_case,
    "space_to_comment": space_to_comment,
    "space_to_plus": space_to_plus,
    "intra_keyword_comment": intra_keyword_comment,
    "equal_to_like": equal_to_like,
    "url_encode": url_encode,
    "double_url_encode": double_url_encode,
    "apostrophe_fullwidth": apostrophe_fullwidth,
}


def mutate(payload: str, techniques: list[str]) -> str:
    """Applique une CHAÎNE de transformations dans l'ordre donné.

    Args:
        payload: charge d'origine.
        techniques: noms de techniques (clés de TAMPER_TECHNIQUES).

    Returns:
        La charge transformée. Une technique inconnue est ignorée.
    """
    result = payload
    for name in techniques:
        fn = TAMPER_TECHNIQUES.get(name)
        if fn is not None:
            result = fn(result)
    return result


def generate_sql_variants(payload: str) -> list[dict[str, str]]:
    """Produit une liste ordonnée de variantes d'évasion d'une charge SQL.

    On va du moins au plus agressif : casse et commentaires (souvent
    suffisants), puis encodages, puis chaînes combinées. Chaque variante est
    dédupliquée et diffère de la charge d'origine.

    Returns:
        Liste de dicts {"technique": <nom lisible>, "payload": <charge mutée>}.
    """
    chains: list[tuple[str, list[str]]] = [
        ("alternate_case", ["alternate_case"]),
        ("space_to_comment", ["space_to_comment"]),
        ("intra_keyword_comment", ["intra_keyword_comment"]),
        ("apostrophe_fullwidth", ["apostrophe_fullwidth"]),
        ("url_encode", ["url_encode"]),
        ("double_url_encode", ["double_url_encode"]),
        ("case+comment", ["alternate_case", "space_to_comment"]),
        ("keyword_comment+case", ["intra_keyword_comment", "alternate_case"]),
        ("comment+url_encode", ["space_to_comment", "url_encode"]),
    ]
    return _build_variants(payload, chains)


def generate_xss_variants(payload: str) -> list[dict[str, str]]:
    """Produit des variantes d'évasion d'une charge XSS.

    Pour le XSS, la casse des balises et les encodages sont les leviers
    principaux ; les commentaires SQL ne s'appliquent pas.
    """
    chains: list[tuple[str, list[str]]] = [
        ("alternate_case", ["alternate_case"]),
        ("url_encode", ["url_encode"]),
        ("double_url_encode", ["double_url_encode"]),
        ("case+url_encode", ["alternate_case", "url_encode"]),
    ]
    return _build_variants(payload, chains)


def _build_variants(
    payload: str,
    chains: list[tuple[str, list[str]]],
) -> list[dict[str, str]]:
    """Applique chaque chaîne, déduplique et écarte les mutations sans effet."""
    variants: list[dict[str, str]] = []
    seen: set[str] = {payload}
    for label, techniques in chains:
        mutated = mutate(payload, techniques)
        if mutated in seen:
            continue
        seen.add(mutated)
        variants.append({"technique": label, "payload": mutated})
    return variants


def is_waf_blocked(
    status_code: int | None,
    headers: dict[str, str] | None,
    body: str | None,
) -> bool:
    """Décide (PUR) si une réponse ressemble à un BLOCAGE WAF (vs une réponse
    applicative normale).

    Autonome (aucun import réseau) pour rester testable hors-ligne. Critère :
    un code de type challenge (403/406/429/503) accompagné d'un marqueur de WAF
    ou d'une page de blocage générique.
    """
    headers_lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    body_lower = (body or "").lower()
    server = headers_lower.get("server", "").lower()

    cloudflare_marker = (
        "cf-ray" in headers_lower
        or "cloudflare" in server
        or "cloudflare" in body_lower
        or "cf-chl" in body_lower
    )
    generic_block = (
        "attention required" in body_lower
        or "access denied" in body_lower
        or "request blocked" in body_lower
        or "request rejected" in body_lower
    )

    if status_code in _CHALLENGE_STATUS_CODES and (cloudflare_marker or generic_block):
        return True
    # Certaines pages de challenge répondent en 200 mais affichent le challenge.
    if cloudflare_marker and generic_block:
        return True
    return False
