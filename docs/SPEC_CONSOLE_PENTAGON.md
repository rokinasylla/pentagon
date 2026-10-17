# Spécification — Console conversationnelle PENTAGON

> Document de référence pour la conception de l'interface de PENTAGON, agent multi-agent de test d'intrusion assisté par LLM (projet de Master 2).
> Il décrit **ce qui est attendu** : le fonctionnel, l'architecture de l'expérience, les écrans, les parcours et les composants — ainsi que le **brief d'identité visuelle**.

## 0. Portée et règles de rédaction

- Ce document spécifie le **quoi** et le **comportement**, pas le **look**.
- **Aucune direction graphique n'est imposée ici** : pas de palette, pas de typographie, pas de style visuel, pas de parti pris esthétique. Ces décisions relèvent de l'**identité visuelle** (§4), qui est un **livrable à produire**, pas une contrainte de ce document.
- Quand un élément doit être « distinguable » ou « hiérarchisé » visuellement (ex. la sévérité d'une faille), le document dit **ce que l'utilisateur doit percevoir**, jamais **par quelle couleur ou forme** — le traitement est laissé à l'identité.
- Public : le concepteur/designer qui produira les écrans, et le jury de soutenance.

---

## 1. Vision et objectifs produit

PENTAGON transforme un pentest — habituellement réservé à des experts, piloté en ligne de commande — en une **conversation** avec un agent autonome qui **prouve** chaque vulnérabilité au lieu de simplement la signaler.

Objectifs de l'interface :
1. **Dialoguer** avec l'agent en langage naturel, comme avec un assistant, plutôt que de cliquer dans des formulaires.
2. **Rendre visible la preuve** : chaque faille est accompagnée de la démonstration concrète qui l'établit, et peut être poussée jusqu'à une exploitation réelle **à la demande de l'opérateur**.
3. **Être utilisable par un non-expert** (ex. le propriétaire d'un site) autant que par un pentester, via des points d'entrée guidés.
4. **Rester gouverné** : toute action offensive est encadrée par les règles d'engagement (RoE), non destructive, et bornée à la preuve.

Promesse centrale : **« un agent qui prouve ce qu'il avance »** — réduire les faux positifs par la démonstration, pas par la confiance.

---

## 2. Utilisateurs et personas

| Persona | Profil | Attentes |
|---|---|---|
| **Opérateur pentester** | Expert sécurité | Contrôle fin, commandes rapides, preuves techniques détaillées, exploitation à la demande, export pour rapport client. |
| **Propriétaire de site non-expert** | Gère un site/VPS, peu de bagage sécurité | Comprendre « suis-je protégé ? » en langage clair, être guidé, obtenir des recommandations actionnables sans jargon. |
| **Administrateur de la plateforme** | Gère comptes et droits | Créer/gérer les comptes opérateur, séparer les rôles, superviser l'usage. *(Rôles admin/testeur déjà présents côté backend.)* |

Le même produit doit servir ces trois profils ; le niveau de langage et de guidage s'adapte (pré-prompts pour le non-expert, commandes directes pour l'expert).

---

## 3. Principes directeurs de l'expérience

1. **Conversation d'abord.** L'unité d'interaction est le message échangé avec l'agent, pas le bouton. Les actions avancées existent aussi comme **commandes** (`/…`), mais tout peut se dire en langage naturel.
2. **Le canevas montre, le fil explique.** À gauche la conversation (intentions, explications, décisions) ; à droite un **canevas** vivant où s'accumulent les résultats structurés (failles, audit, rapport).
3. **La preuve est un objet de première classe.** Chaque faille porte un **état de preuve** et, lorsqu'elle existe, la trace qui la démontre.
4. **L'opérateur garde la main sur l'offensif.** L'exploitation poussée ne se déclenche jamais seule : elle est demandée explicitement, et reste non destructive.
5. **Gouvernance visible.** Le périmètre autorisé (RoE) est affiché en permanence ; ce qui est hors périmètre est refusé et expliqué.
6. **Clarté pour tous.** Tout résultat technique a une formulation compréhensible par un non-expert, consultable au besoin.

---

## 4. Identité visuelle et marque *(livrable à créer — brief, non résolu ici)*

> **Important.** La plateforme doit posséder une **identité visuelle propre** : ce n'est pas un habillage optionnel, c'est un livrable attendu. Ce document **ne choisit pas** les couleurs, les polices ni le style — il définit l'**intention** que l'identité devra servir, et la laisse entièrement ouverte.

### 4.1 Ce qui est attendu comme livrables d'identité
- **Nom de marque** de la plateforme (PENTAGON peut rester le nom de code ; un nom commercial peut être proposé).
- **Logo** : un symbole (marque figurative) + un logotype (le nom composé), déclinables.
- **Déclinaisons du logo** : version complète, version compacte (symbole seul pour la barre de navigation), version monochrome, versions pour fonds clairs et foncés.
- **Icône d'application / favicon**.
- **Système d'icônes** cohérent (navigation, actions, catégories de failles).
- **Système visuel** : palette, typographies, échelles, traitements de surface, états — **à définir par l'identité** (hors de ce document).
- **Ton de voix** de l'agent (déjà amorcé : « détecter en prouvant, jamais ravager ») : registre, niveau de langage, formulation des preuves.
- **Guide d'usage** minimal (do/don't, zones de protection du logo, usages interdits).

### 4.2 Attributs de marque à exprimer *(à valider, pistes de départ)*
L'identité devra traduire, par ses propres moyens graphiques :
- **Rigueur et fiabilité** — on prouve, on ne prétend pas.
- **Maîtrise et retenue** — un outil offensif responsable, jamais spectaculaire ni anxiogène.
- **Clarté** — accessible à un non-expert sans paraître simpliste pour un expert.
- **Crédibilité professionnelle** — à la hauteur d'un livrable de pentest remis à un client.

*(Ces attributs orientent l'identité ; ils ne dictent aucune couleur ni police.)*

### 4.3 Où l'identité s'applique
Logo dans la barre de navigation et l'écran d'accueil ; favicon ; en-têtes du rapport PDF exporté ; écran de connexion ; avatar/signature de l'agent dans la conversation ; page de partage d'un rapport.

---

## 5. Architecture de l'expérience

### 5.1 Disposition générale
Une application à **trois zones** :
- **Barre de navigation** (persistante) : accès aux grandes sections — Missions, Sessions, Audits, Rapports, Réglages — et au compte.
- **En-tête de session** : cible courante, périmètre autorisé (RoE), état de l'agent, opérateur.
- **Espace de travail en deux panneaux** :
  - **Panneau conversation** (gauche) : le fil avec l'agent + la zone de saisie.
  - **Panneau canevas** (droite) : les résultats structurés, organisés en onglets.

### 5.2 Sections principales
- **Missions** : créer et retrouver des missions (une mission = une cible + un périmètre).
- **Sessions** : les conversations/campagnes en cours ou passées, avec leur historique (persisté).
- **Audits** : la vue durcissement serveur/VPS.
- **Rapports** : les synthèses exportables.
- **Réglages** : compte, rôles, préférences, gestion des utilisateurs (admin).

### 5.3 Onglets du canevas
- **Findings** — les vulnérabilités applicatives, chacune avec sévérité, catégorie, évidence, état de preuve, actions.
- **Audit** — la posture de durcissement de l'hôte et du domaine.
- **Rapport** — la synthèse chiffrée et l'export.

---

## 6. Spécifications fonctionnelles

### 6.1 Authentification et rôles
- Connexion obligatoire (jamais de console offensive ouverte).
- Deux rôles au moins : **administrateur** (gère comptes/droits) et **testeur/opérateur** (mène les campagnes). Séparation stricte des privilèges.
- Expiration de session par inactivité.
- *(Base déjà présente côté backend : login, rôles admin/user, gestion des comptes, expiration.)*

### 6.2 Création d'une mission
- Saisir la **cible** (URL/domaine).
- Choisir le **périmètre autorisé (RoE)** parmi des catégories : reconnaissance passive, scan actif, exploitation. **Deny-by-default** : rien n'est autorisé qui n'ait été coché.
- Option de **périmètre interactif** : autoriser, après la reconnaissance, l'extension du périmètre à des cibles découvertes (asset par asset, validation humaine explicite).
- Choix du **moteur d'orchestration** : séquentiel (défaut) ou graphe parallèle. *(Les deux existent côté backend.)*
- Rappel légal : l'accord technique n'emporte pas l'autorisation légale.

### 6.3 Conversation avec l'agent
- Saisie en **langage naturel** : l'opérateur décrit son besoin, l'agent planifie et agit sous RoE.
- **Commandes** (slash) pour les actions précises et répétables (voir §6.4).
- **Pré-prompts** (suggestions) pour démarrer, surtout pour le non-expert ; un clic insère une instruction prête.
- L'agent répond dans le fil avec : résumé en clair, phases exécutées, outils mobilisés, et renvois vers le canevas.
- États de l'agent visibles : au repos, en travail (par phase), en attente d'une décision de l'opérateur, bloqué (hors RoE).
- Un seul travail lourd actif à la fois par session ; progression diffusée en continu (streaming).

### 6.4 Catalogue de commandes *(liste cible, extensible)*
| Commande | Effet |
|---|---|
| `/scan` | Lance reconnaissance + scan sous le RoE courant. |
| `/exploit <n>` | Exploite à la demande la faille n° *n* (bornée à la preuve) → la fait passer à **Confirmé**. |
| `/confirm <n>` | Rejoue la démonstration d'une faille pour confirmer qu'elle est toujours exploitable (re-test). |
| `/audit` | Lance/affiche l'audit de durcissement serveur/VPS. |
| `/report` | Génère la synthèse et ouvre l'onglet Rapport. |
| `/scope` | Affiche ou étend (si autorisé) le périmètre. |
| `/stop` | Interrompt l'action en cours. |

Toutes les commandes doivent avoir un **équivalent en langage naturel** et être **découvrables** (aide, autocomplétion).

### 6.5 Modèle de preuve : Détecté → Prouvé → Confirmé
C'est le cœur anti-faux-positifs. Chaque faille porte un de ces trois états :
1. **Détecté** — un candidat est repéré (par un outil et/ou corrélation à une base de vulnérabilités connues).
2. **Prouvé** — une démonstration **automatique et non destructive** établit la faille (ex. jeton réellement forgé et accepté, expression réellement évaluée par le serveur, fichier témoin réellement lu, charge réellement exécutée dans un navigateur).
3. **Confirmé** — une **exploitation poussée, déclenchée par l'opérateur** (`/exploit`), démontre l'impact réel (ex. accéder effectivement aux données d'un autre compte avec le jeton forgé), toujours bornée à la preuve, sans exfiltration ni écriture destructive.

Attendus associés :
- L'interface doit rendre cet état **immédiatement lisible** par faille, et montrer la **trace** à chaque étape franchie.
- Le passage à **Confirmé** est une action explicite, jamais automatique.
- L'agent doit pouvoir agir **comme un humain dans le site** quand c'est nécessaire (parcours navigateur piloté : connexion, saisie dans des formulaires, envoi) et pas seulement via des scripts — cette capacité existe déjà pour un cas (confirmation XSS en navigateur) et doit être généralisée.
- Chaque faille indique aussi un **niveau de confiance** et sa **catégorie** (OWASP/CWE).

### 6.6 Canevas — Findings
Pour chaque faille : titre lisible, **sévérité**, catégorie (OWASP/CWE), **évidence** (extrait de preuve, sans donnée sensible brute), **état de preuve** (§6.5), **actions** (ex. « Confirmer par exploitation », « Revoir la preuve »). Tri par sévérité puis par stade de preuve. Les failles **confirmées** priment dans le risque global.

### 6.7 Canevas — Audit serveur / VPS
Au-delà de l'application : posture de **durcissement** de l'hôte et du domaine. Contrôles attendus (déjà outillés côté backend) : TLS/SSL, en-têtes de sécurité HTTP, méthodes HTTP, ports/services exposés, DNS & e-mail (SPF/DKIM/DMARC), corrélation CVE des composants détectés. Chaque contrôle : un **verdict** (bon / à corriger / exposé), une explication en clair, une recommandation. Une **posture globale** synthétique.

### 6.8 Canevas — Rapport et export
Synthèse : comptes par sévérité, nombre de failles **prouvées/confirmées**, **couverture OWASP**, risque global. **Export PDF** (déjà implémenté côté backend) et **partage** d'un lien. Le rapport doit être présentable à un client.

### 6.9 Persistance et historique
Les campagnes survivent au redémarrage (source de vérité sur disque, déjà en place). L'historique des sessions est consultable et rouvrable (revoir le bilan, ré-exporter) sans relancer. Un **re-test** ciblé rejoue le seul testeur concerné (preuve de non-régression après correction).

### 6.10 Assistant conversationnel transverse
Un assistant (déjà amorcé côté backend) répond aux questions de l'opérateur dans le fil (expliquer une faille, vulgariser pour un non-expert, proposer la prochaine action) — distinct de l'exécution offensive, qui reste gouvernée.

---

## 7. Spécifications UI/UX *(structure et comportement ; aucun style imposé)*

> Les composants sont décrits par leur **rôle, contenu, états et comportement**. Leur apparence (couleur, forme, typographie, animation) relève de l'identité (§4) et n'est pas fixée ici.

### 7.1 Inventaire des composants
- **Barre de navigation** : symbole de marque + entrées de section + accès compte. Une entrée active est distinguable.
- **En-tête de session** : nom de session, cible, **badge RoE**, indicateur d'état agent, opérateur.
- **Fil de conversation** : messages opérateur vs agent nettement distincts ; un message agent peut contenir des blocs structurés (phases, outils mobilisés, bloc de preuve, renvoi vers le canevas).
- **Zone de saisie (composer)** : champ de message ; rangée de commandes suggérées ; indication qu'un `/` ouvre les commandes ; envoi.
- **Chips de pré-prompts** : suggestions cliquables, surtout en état initial.
- **Onglets du canevas** : Findings / Audit / Rapport, avec compteur le cas échéant.
- **Carte de faille** : titre, sévérité (codée visuellement), catégorie, évidence, **tracker de preuve** (Détecté → Prouvé → Confirmé), actions.
- **Tracker de preuve** : représentation claire des trois stades et du stade atteint.
- **Lignes d'audit** : intitulé du contrôle, verdict, détail/recommandation.
- **Tuiles de synthèse** (rapport) : nombres clés par sévérité ; set de catégories OWASP couvertes ; actions d'export/partage.

### 7.2 États à prévoir pour chaque vue
- **Vide** (aucune mission / aucune faille encore) : expliquer quoi faire ensuite, proposer une première action — jamais un écran mort.
- **Chargement / en cours** : progression lisible, idéalement par phase.
- **Rempli** : état nominal.
- **Erreur / hors RoE / action refusée** : message clair qui explique la cause et la marche à suivre, sans jargon ni rejet brut.
- **Bloqué en attente d'une décision** (ex. extension de périmètre) : l'action requise de l'opérateur est explicite.

### 7.3 Micro-interactions attendues
- Insertion d'un pré-prompt dans la saisie en un clic.
- Autocomplétion / aide des commandes.
- Mise à jour **en direct** du canevas pendant que l'agent travaille (streaming).
- Transition visible d'une faille lorsqu'elle change d'état de preuve.
- Ouverture du détail/preuve d'une faille.

### 7.4 Responsive
- Doit fonctionner du grand écran au mobile. En petite largeur, les deux panneaux se réorganisent (empilement ou bascule chat/canevas) sans perte de fonction.

### 7.5 Accessibilité
- Contrastes suffisants (quelle que soit la palette retenue), focus clavier visible, navigation au clavier, cibles tactiles suffisantes, respect des préférences de réduction de mouvement, libellés explicites. L'information ne doit **jamais** passer uniquement par la couleur (la sévérité et les verdicts doivent rester lisibles sans elle).

---

## 8. Parcours utilisateur (flux de référence)

1. **Connexion** → tableau des missions/sessions.
2. **Nouvelle mission** : cible + périmètre (RoE) + moteur → lancement.
3. **Conversation** : l'opérateur demande (langage naturel ou `/scan`) ; l'agent exécute OSINT → Scan → Web App ; le canevas se peuple de failles **Détecté/Prouvé**.
4. **Compréhension** : l'opérateur consulte une faille, lit l'évidence ; un non-expert demande « est-ce grave ? » et obtient une explication claire.
5. **Exploitation à la demande** : `/exploit <n>` → l'agent démontre l'impact réel → la faille passe **Confirmé** (trace dans le canevas).
6. **Audit serveur** : `/audit` → posture de durcissement de l'hôte/VPS.
7. **Rapport** : `/report` → synthèse + export PDF / partage.
8. **Plus tard** : réouverture de la session depuis l'historique ; **re-test** après correction.

Flux secondaires : extension de périmètre supervisée ; action hors RoE refusée et expliquée ; interruption (`/stop`) ; gestion des comptes (admin).

---

## 9. Contraintes et ancrage technique *(existant à réutiliser)*

- Backend **Flask** avec diffusion en continu (SSE) ; un job actif par session ; endpoints déjà en place (plan, start, stream, result, jobs, report, download, evaluate, chat, gestion comptes/politique).
- **Orchestrateur** séquentiel **et** graphe (LangGraph) sélectionnables.
- **RoE Enforcer** « deny-by-default » : garde-fou de chaque action ; périmètre statique ou interactif.
- **Agents** : OSINT, Scanning, Web App, Exploitation, Reporting.
- **Outils** offensifs/analytiques existants (auth, JWT, IDOR, SQLi, XSS navigateur, LFI, open redirect, SSTI, SSRF, CSRF, TLS, en-têtes, méthodes HTTP, DNS/e-mail, exposition réseau, CVE…).
- **Persistance** des campagnes sur disque ; historique rechargé au démarrage.
- **Export PDF** opérationnel.
- Déploiement cible : plateforme authentifiée accessible à distance (actuellement VM + reverse-proxy TLS).

L'interface est une **nouvelle couche de présentation** par-dessus ce socle : elle ne redéfinit pas le moteur, elle l'expose en conversationnel.

---

## 10. Phasage proposé (indicatif)

- **Lot UI-1** — Coquille conversationnelle : disposition, conversation + canevas, Findings en lecture, pré-prompts, commandes de base. Branchée sur l'existant.
- **Lot UI-2** — Modèle de preuve complet : état par faille, exploitation à la demande (`/exploit`, `/confirm`), généralisation des actions navigateur.
- **Lot UI-3** — Audit serveur/VPS et rapport interactif + export/partage.
- **Lot UI-4** — Historique, re-test, périmètre interactif dans l'UI, gestion fine des rôles.
- **Transverse** — Identité visuelle (§4) appliquée à l'ensemble.

Hors-scope de cette première spec : facturation, multi-tenant, marketplace d'outils.

---

## 11. Glossaire

- **RoE (Rules of Engagement)** — périmètre et catégories d'actions autorisées ; « deny-by-default ».
- **OWASP Top 10** — référentiel des risques web majeurs.
- **CWE** — nomenclature des types de faiblesses.
- **PTES** — méthodologie de test d'intrusion par phases.
- **Faux positif** — faille signalée qui n'en est pas une ; combattue ici par le modèle Détecté → Prouvé → Confirmé.
- **Non destructif** — une démonstration bornée à la preuve, sans dommage ni exfiltration.
- **Canevas** — le panneau de résultats structurés, à droite de la conversation.

---

*Fin de la spécification. Ce document fixe les attentes fonctionnelles, l'expérience et le brief d'identité ; il laisse délibérément ouverts tous les choix graphiques, qui seront portés par l'identité visuelle à créer.*
