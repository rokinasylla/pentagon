# Feuille de route — implémentation de la console PENTAGON

> Plan d'implémentation de la **console conversationnelle** et de la **dynamique de preuve** (Détecté → Prouvé → Confirmé) par-dessus le socle PENTAGON existant.
> Références : [SPEC_CONSOLE_PENTAGON.md](SPEC_CONSOLE_PENTAGON.md) (quoi/comportement) et la maquette UI (12 écrans) qui fixe la cible visuelle.
> Ce document traite le **comment** : lots, refactors backend, contrat d'API, jalons démontrables. Aucun choix graphique ici (porté par l'identité/maquette).

## 0. Principe directeur

On ne réécrit pas le moteur : on **expose** le socle existant (orchestrateur, RoE, agents, outils, persistance, export PDF) derrière une **API stable**, et on construit la console par-dessus. Chaque lot se termine par quelque chose de **démontrable** (utile pour la soutenance), et ne casse ni la CLI `pentagon.py` ni la console web actuelle tant que la bascule n'est pas faite.

Règle d'or de la dynamique offensive : toute exécution (y compris l'exploitation « à la demande ») reste **gouvernée par le RoE** et **bornée à la preuve**, non destructive.

---

## 1. État des lieux

### Déjà en place (à réutiliser)
- **Backend Flask** (`webapp.py`) : auth + rôles admin/testeur, expiration de session, SSE (`/api/stream`), un job actif par session, persistance des campagnes sur disque + historique rechargé au démarrage, endpoints `plan / start / stream / result / jobs / report / evaluate / download / chat / admin.*`.
- **Orchestration** : séquentielle (`orchestrator.py`) et graphe (`orchestrator_graph.py`), sélectionnables.
- **RoE Enforcer** « deny-by-default » : périmètre statique + extension interactive (`add_authorized_target`, `scope_authorizer`).
- **5 agents** (OSINT, Scanning, Web App, Exploitation, Reporting) + **outils** (auth, JWT, IDOR, SQLi, XSS navigateur, LFI, open redirect, SSTI, SSRF, CSRF, TLS, en-têtes, méthodes HTTP, DNS/e-mail, exposition réseau, CVE).
- **Export PDF** (Reporting) et **métriques** précision/rappel (Lot 6).
- **Assistant conversationnel** amorcé (`/api/chat`).

### À construire (l'écart)
1. **Front « console »** conforme à la maquette (12 écrans) — aujourd'hui l'UI est un `templates/index.html` à étapes/boutons.
2. **Dynamique de preuve par faille** : un **état** (détecté/prouvé/confirmé) porté par chaque faille, persistant, et affiché.
3. **Exploitation à la demande** : aujourd'hui l'agent Exploitation exécute **tous** les testeurs en un seul passage ; il faut pouvoir **rejouer un testeur ciblé sur UNE faille** en mode « confirmation » (plus poussé, toujours borné).
4. **Actions « comme un humain »** généralisées : le pilotage navigateur (Playwright) n'existe que pour le XSS → en faire un **exécuteur d'actions** réutilisable (connexion, saisie de formulaire, capture DOM) pour les confirmations.
5. **Dispatch de commandes** (`/scan`, `/exploit`, `/confirm`, `/audit`, `/report`, `/scope`, `/stop`) + équivalents langage naturel.
6. **Vues** audit serveur, rapport interactif, **partage public** en lecture seule, historique/re-test, états (vide/refus/attente).

---

## 2. Fondations techniques (préalable transverse)

**F1 — Modèle de données « Finding » de première classe.**
Aujourd'hui les résultats vivent dans le JSON de campagne. Introduire un objet **Finding** identifiable et persistant :
```
Finding = { id, session_id, title, severity, owasp, cwe, category,
            proof_state: "detected"|"proven"|"confirmed",
            evidence: [ {stage, tool, snippet, at} ],
            confidence, affected_endpoint, created_at, updated_at }
```
- Dérivé des sorties d'outils + du jugement LLM lors de la campagne.
- `proof_state` initial : `proven` pour ce que les testeurs prouvent déjà en passage auto, `detected` pour ce qui n'est que corrélé (ex. CVE).
- Stocké à côté des campagnes (même source de vérité disque), indexable par session.

**F2 — Contrat d'API stable et versionné** (`/api/v1/...`), additif à l'existant. Voir §4.

**F3 — Décision d'architecture front : TRANCHÉE → front dédié React + Vite.**
Options envisagées (sans incidence sur le backend) : *(a)* enrichir le front
vanilla JS existant (moindre coût mais faible fidélité à la maquette
conversationnelle et état des findings fragile) ; *(b)* front dédié consommant
l'API (meilleure fidélité) ; *(c)* front dédié avec framework complet.
**Choix retenu : (c) — SPA React + Vite** consommant l'API v1, pour l'état des
findings (tracker Détecté→Prouvé→Confirmé en direct), le routing multi-écrans et
la fidélité aux 12 artboards. Le backend expose la même API quel que soit le front.
Recommandation de déploiement : build Vite → fichiers statiques servis par Flask
(un seul artefact, pas de second serveur), ou dev-server Vite proxifiant `/api`.

---

## 3. Lots d'implémentation

Chaque lot : objectif · backend · front · **démontrable** · critères d'acceptation.

### Lot UI-1 — Coquille conversationnelle *(écrans 01, 02, 03, 04 en lecture)*
**Objectif** : se connecter, créer une mission, lancer une campagne et voir les failles arriver, dans la disposition conversation + canevas.
- **Backend** : formaliser `missions`/`sessions` (création, liste, détail) au-dessus de `start`/`jobs` ; exposer les **Findings** (F1) via l'API ; brancher le fil sur `/api/chat` + SSE pour la progression.
- **Front** : écran de connexion ; tableau missions/sessions ; formulaire *nouvelle mission* (cible + RoE + moteur) ; console à deux panneaux (fil + canevas) ; onglet **Findings** en lecture ; pré-prompts ; streaming live.
- **Démontrable** : depuis la console, lancer une vraie campagne sur la cible de démo et voir les findings se peupler en direct.
- **Acceptation** : une campagne complète se pilote sans CLI ; les findings affichent sévérité, catégorie, état `détecté/prouvé` ; RoE visible ; reconnexion/refresh sans perte (persistance).

### Lot UI-2 — Commandes & dynamique de preuve *(écrans 04 actions, 05 détail)* — **cœur du projet**
**Objectif** : passer une faille de *Prouvé* à *Confirmé* par exploitation à la demande, et le montrer.
- **Backend** :
  - **Refactor de l'agent Exploitation** : extraire chaque testeur en **action ciblable** `exploit(finding, mode)` avec `mode = "prove" | "confirm"`. Le mode *confirm* pousse la démonstration d'un cran (ex. avec le jeton forgé, lire effectivement une ressource d'autrui), **toujours non destructif et sous RoE**.
  - **Exécuteur d'actions navigateur** : généraliser `xss_browser_tool` en un service réutilisable (connexion par clics, saisie de formulaire, envoi, capture d'un indicateur dans le DOM) pour les confirmations qui nécessitent d'agir « comme un humain ».
  - **Dispatcher de commandes** : router `/scan /exploit <n> /confirm <n> /audit /report /scope /stop` **et** leurs formulations naturelles vers les actions du moteur, chaque action re-vérifiée par le RoE.
  - Mettre à jour le `proof_state` et l'historique d'évidence du Finding (F1).
- **Front** : barre de commandes + autocomplétion ; **carte de faille** avec **tracker** Détecté→Prouvé→Confirmé ; bouton « Confirmer par exploitation » ; **drawer de détail** (preuve technique + explication vulgarisée + confiance + catégorie).
- **Démontrable** : `/exploit 1` sur une faille JWT → l'agent démontre l'accès réel → la carte passe **Confirmé** avec la trace.
- **Acceptation** : l'exploitation à la demande ne part jamais seule ; refus propre si hors RoE ; la confirmation reste non destructive (aucune écriture/exfiltration) ; l'état et la preuve sont persistés.

### Lot UI-3 — Audit serveur & rapport *(écrans 06, 07, 10)*
**Objectif** : exposer l'audit de durcissement et le rapport, avec export et partage.
- **Backend** : vue **Audit** structurée à partir des outils Lot 1 (TLS, en-têtes, méthodes HTTP, exposition réseau, DNS/e-mail, CVE) avec verdict + recommandation par contrôle + posture globale ; **rapport interactif** (réutilise `report`/`evaluate`/`download`) ; **partage public** en lecture seule via **jeton** (`/share/<token>`), sans la console offensive.
- **Front** : onglet **Audit**, onglet **Rapport** (synthèse, sévérités, couverture OWASP, export PDF, lien de partage) ; **pages d'index Audits et Rapports** (vues d'ensemble, par cas/en-tête) ; **page de partage** publique.
- **Démontrable** : audit du VPS de démo + export PDF + lien partageable consultable sans compte.
- **Acceptation** : chaque contrôle a un verdict lisible (sans dépendre de la couleur seule) ; le lien de partage n'expose ni action ni donnée sensible brute ; l'export PDF correspond au rapport affiché.

### Lot UI-4 — Historique, re-test, périmètre interactif, états *(écrans 08, 11)*
**Objectif** : revivre une session, re-tester après correction, superviser l'extension de périmètre, couvrir les états.
- **Backend** : **re-test ciblé** (rejouer le seul testeur d'une faille → preuve de non-régression) ; **périmètre interactif** exposé (valider asset par asset via le `scope_authorizer`) ; signaux d'**états** (vide, refus RoE, attente de décision).
- **Front** : historique rouvrable (revoir le bilan, ré-exporter sans relancer) ; action **re-test** sur une faille ; dialogue d'extension de périmètre ; états **vide / refus / attente** soignés.
- **Démontrable** : rouvrir une campagne passée ; re-tester une faille « corrigée » → passe en non-régression ; refuser proprement une action hors périmètre.
- **Acceptation** : aucune action offensive n'élargit le périmètre sans validation humaine explicite ; les états ne sont jamais des écrans morts.

### Lot UI-5 — Comptes/admin, sites autorisés, responsive, identité *(écrans Admin, Espace opérateur, Mobile, Identité)*
**Objectif** : finir la plateforme multi-utilisateur, la restriction par site, et l'habillage.
- **Backend** : gestion comptes/rôles (déjà présente) ; **sites autorisés par opérateur** — associer à chaque compte la liste des cibles qu'il a le droit de tester (ACL), gérée par l'admin ; filtrer missions et création de mission par cette liste (recoupe le RoE mais au niveau du compte, pas de la campagne).
- **Front** : écran **Admin** (comptes + sites autorisés) ; **Espace opérateur** (vue restreinte à ses propres sites) ; **responsive** mobile (bascule chat/canevas) ; application complète de l'**identité visuelle** (artboard « Identité »).
- **Démontrable** : un admin crée un opérateur et lui autorise un site ; cet opérateur ne voit/teste que ce site ; la console bascule proprement chat/canevas sur mobile.
- **Acceptation** : séparation stricte des privilèges ; un opérateur ne peut pas lancer de mission hors de ses sites autorisés ; parcours clés utilisables sous ~400 px.

---

## 3bis. Correspondance écrans finalisés → lots

La maquette de design arrêtée (artefact « PENTAGON — Console », 12 artboards) se répartit ainsi :

| Artboard finalisé | Lot |
|---|---|
| Connexion | UI-1 |
| Espace opérateur / Missions (accès limité à ses sites) | UI-1 (+ ACL en UI-5) |
| Nouvelle mission — périmètre (RoE) | UI-1 |
| Console · onglet Findings (session) | UI-1 (lecture) → UI-2 (actions) |
| Faille — preuve & exploitation à la demande | **UI-2** |
| Console · onglet Audit + Audits-Index | UI-3 |
| Console · onglet Rapport + Rapports-Index | UI-3 |
| Partage de rapport (public) | UI-3 |
| Historique & re-test, états (vide/refus/attente) | UI-4 |
| Admin — comptes & sites autorisés | UI-5 |
| Vue mobile — bascule chat/canevas | UI-5 |
| Identité visuelle | transverse (appliquée partout) |

## 4. Contrat d'API (ajouts, `/api/v1`)

| Méthode & route | Rôle | S'appuie sur |
|---|---|---|
| `POST /missions` | Créer une mission (cible, RoE, moteur) | `RoEEnforcer.from_user_input`, `start` |
| `GET /missions` · `GET /missions/:id` | Lister / détailler | `jobs`, persistance |
| `GET /sessions/:id/findings` | Findings + `proof_state` | F1 |
| `POST /sessions/:id/command` | Dispatcher NL + slash | §Lot UI-2 |
| `POST /findings/:id/exploit` | Exploitation à la demande (→ confirmé) | agent Exploitation refactoré |
| `POST /findings/:id/retest` | Re-test ciblé | idem |
| `GET /sessions/:id/audit` | Vue audit durcissement | outils Lot 1 |
| `GET /sessions/:id/report` · `POST …/share` | Rapport + lien public | `report`, `download` |
| `GET /share/:token` | Rapport public (lecture seule) | nouveau |
| `POST /sessions/:id/scope` | Extension de périmètre supervisée | `scope_authorizer` |
| `admin/users` · `admin/policy` | Comptes & politique | existant |
| `admin/users/:id/sites` | Sites autorisés d'un opérateur (ACL) | nouveau (UI-5) |

Le streaming de progression reste sur **SSE** (`/api/stream`), étendu pour émettre aussi les **changements d'état de faille**.

---

## 5. Risques & points d'attention

- **Gouvernance** : chaque action du dispatcher (surtout `/exploit`, `/confirm`, `/scope`) repasse par le RoE ; en mode non-interactif, pas d'élargissement de périmètre.
- **Borne de non-destruction** : le mode *confirm* doit rester prouvant, jamais destructeur (pas d'écriture, pas d'exfiltration réelle) — à encadrer par des garde-fous explicites dans l'exécuteur.
- **Déterminisme LLM** : conserver `json_mode` et la réparation de JSON déjà en place ; l'état de faille ne doit pas dépendre d'un parsing fragile.
- **Navigateur piloté** : Playwright est coûteux et parfois « flaky » ; borner les timeouts, isoler les sessions, échouer proprement.
- **Partage public** : jeton signé, lecture seule, aucune donnée sensible brute, révocable.
- **Compatibilité** : garder CLI et console actuelle fonctionnelles jusqu'à la bascule complète.

---

## 6. Jalons & valeur de soutenance

| Jalon | Contenu | Ce qu'on démontre |
|---|---|---|
| **J1** | Lot UI-1 | « Je pilote un pentest par la conversation, les failles arrivent en direct. » |
| **J2** | Lot UI-2 | « L'agent **prouve** qu'une faille est réellement exploitable, à ma demande. » *(message central)* |
| **J3** | Lot UI-3 | « Audit serveur + rapport exportable et partageable. » |
| **J4** | Lot UI-4 | « Historique, re-test de non-régression, périmètre supervisé. » |
| **J5** | Lot UI-5 | « Plateforme multi-utilisateur, mobile, identité aboutie. » |

Priorité absolue : **J1 puis J2** (la dynamique de preuve est le différenciateur du mémoire). J3–J5 complètent la plateforme.

---

## 7. Définition de « fini » (transverse, chaque lot)
- Tests purs des nouvelles logiques backend (comme l'existant), sans réseau.
- Non-régression sur le banc d'évaluation (métriques précision/rappel, Lot 6).
- Gouvernance RoE vérifiée sur chaque nouvelle action.
- Fonctionne de l'écran large au mobile ; information jamais portée par la seule couleur.
- Déployable sur la VM existante (Flask + reverse-proxy TLS).

---

*Cette feuille de route séquence l'implémentation sans figer la pile front ni les choix graphiques. Elle met au centre, dès le jalon J2, la capacité qui fonde le projet : un agent qui prouve — à la demande et sous contrôle — ce qu'il avance.*
