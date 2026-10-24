"""
Garde de périmètre (scope guard) pour PENTAGON.

PROBLÈME RÉSOLU — la FUITE DE PÉRIMÈTRE en cours de campagne.
Le RoE autorise un agent au niveau de la CIBLE de campagne, mais les agents
dérivent ensuite leurs endpoints de l'analyse (bundle JS, routes découvertes…).
Rien ne garantissait que ces endpoints restent sur la cible : une URL tierce
glissée dans un bundle (p. ex. un lien de documentation de framework) pouvait
devenir la « base d'API » et recevoir de VRAIES attaques — hors du périmètre
explicitement autorisé.

Cette garde est PURE (aucun réseau) et deny-by-default. Elle répond à une seule
question : « cet hôte est-il dans le périmètre de la campagne ? »
  - même hôte que la cible de campagne                       → autorisé ;
  - OU explicitement autorisé par le RoE (scope_check fourni) → autorisé ;
  - sinon                                                     → REFUSÉ.

Un sous-domaine du même domaine racine (p. ex. dev.nafar.tech pour nafar.tech)
n'est PAS autorisé d'office : c'est un AUTRE hôte, qui doit passer par une
autorisation explicite du RoE (élargissement supervisé du périmètre). La garde
ne relâche donc jamais la gouvernance ; `same_site`/`registrable_domain` servent
seulement à *repérer* des assets liés à SURFACER (jamais à attaquer d'office).
"""

from urllib.parse import urlparse

# Suffixes publics à deux niveaux les plus courants (eTLD approximatif, sans
# dépendance externe). Suffisant pour borner un périmètre de façon conservatrice.
_MULTI_LABEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.br", "com.au",
    "co.za", "com.cn", "co.in", "com.tr", "com.mx", "co.kr", "com.sg",
    "com.ng", "com.gh", "org.za",
}


def host_of(url: str) -> str:
    """Hôte (netloc sans identifiants ni port) d'une URL ou d'un domaine nu."""
    if not url:
        return ""
    s = str(url).strip().lower()
    if not s.startswith(("http://", "https://")):
        s = "https://" + s
    netloc = urlparse(s).netloc
    return netloc.split("@")[-1].split(":")[0]  # retire user:pass@ et :port


def registrable_domain(host: str) -> str:
    """
    Domaine enregistrable approximatif (eTLD+1), sans dépendance externe.

    "dev.nafar.tech" -> "nafar.tech" ; "a.b.co.uk" -> "b.co.uk".
    Heuristique conservatrice : en cas de doute, ne fusionne pas deux domaines.
    """
    host = (host or "").strip(".").lower()
    if not host or "." not in host:
        return host
    labels = host.split(".")
    last2 = ".".join(labels[-2:])
    if last2 in _MULTI_LABEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last2


def same_site(a: str, b: str) -> bool:
    """True si a et b partagent le même domaine enregistrable (sous-domaines compris)."""
    ra = registrable_domain(host_of(a))
    rb = registrable_domain(host_of(b))
    return bool(ra) and ra == rb


def host_in_scope(url: str, target_url: str, scope_check=None) -> bool:
    """
    Deny-by-default : l'URL est-elle dans le périmètre autorisé de la campagne ?

    Autorisée si — et seulement si :
      - son hôte est EXACTEMENT celui de la cible de campagne ; OU
      - le RoE l'autorise explicitement via scope_check(url) -> {"allowed": bool}.

    Tout autre hôte (tiers, mais aussi un sous-domaine non autorisé) est REFUSÉ.
    Une URL vide/illisible est refusée. Un scope_check qui lève vaut refus.

    Args:
        url: URL ou hôte à vérifier (la cible d'une requête d'outil).
        target_url: la cible de la campagne (son hôte = périmètre implicite).
        scope_check: callable optionnel (url) -> dict avec clé "allowed".
            Typiquement `RoEEnforcer.check_target`. Injecté par l'orchestrateur.
    """
    h = host_of(url)
    if not h:
        return False
    if h == host_of(target_url):
        return True
    if scope_check is not None:
        try:
            return bool(scope_check(url).get("allowed"))
        except Exception:
            return False
    return False
