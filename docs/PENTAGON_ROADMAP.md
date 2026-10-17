# PENTAGON — Plan de route vers un outil « pro »

> De prototype académique validé à outil professionnel.
> Ce document décline les **améliorations en lots priorisés**, et **détaille les process et workflows** qui seront mis en place pour chacun.
>
> Il s'appuie sur les limites identifiées (voir [PENTAGON_LIMITES.md](PENTAGON_LIMITES.md), axes **L1→L9**).

---

## 1. Vision cible

Passer d'un outil **séquentiel, local, mono-opérateur, centré Top 10 web** à une **plateforme d'audit continue, multi-utilisateur, extensible et gouvernée**, capable de couvrir web + infra, de découvrir sa surface d'attaque, et de prouver ses résultats à grande échelle.

```mermaid
flowchart LR
    subgraph Auj["Aujourd'hui (prototype validé)"]
        A1["Séquentiel"]
        A2["Local / mono-job"]
        A3["Top 10 web"]
        A4["Rapport PDF"]
    end
    subgraph Cible["Cible (pro)"]
        B1["Orchestration LangGraph<br/>parallèle + reprise"]
        B2["Plateforme authentifiée<br/>multi-campagnes"]
        B3["Web + infra + découverte<br/>+ CVE"]
        B4["Rapports interactifs<br/>+ re-test"]
    end
    Auj ==>|plan de route| Cible
```

---

## 2. Méthode de priorisation

Chaque amélioration est notée sur **Valeur** (impact soutenance + utilité pro) et **Effort** (charge de dev + risque). On traite d'abord le quadrant **forte valeur / faible effort** (« quick wins »).

```mermaid
quadrantChart
    title Valeur vs Effort
    x-axis "Faible effort" --> "Fort effort"
    y-axis "Faible valeur" --> "Forte valeur"
    quadrant-1 "Chantiers majeurs"
    quadrant-2 "Quick wins (à faire d'abord)"
    quadrant-3 "Optionnels"
    quadrant-4 "À éviter / différer"
    "Lot 1 Couverture élargie": [0.30, 0.85]
    "Lot 2 Exploitation avancée": [0.60, 0.78]
    "Lot 3 Découverte/Fuzzing": [0.72, 0.62]
    "Lot 4 Orchestration LangGraph": [0.68, 0.80]
    "Lot 5 Plateforme web pro": [0.78, 0.90]
    "Lot 6 Qualité & métriques": [0.45, 0.70]
```

---

## 3. Les lots (vue d'ensemble)

| Lot | Titre | Axes couverts | Valeur | Effort | Phase |
|---|---|---|---|---|---|
| **1** | Couverture élargie (détection) | L1 (partiel), L2 | ⭐⭐⭐ | 🔧 | V1.1 |
| **2** | Exploitation avancée | L1 (reste) | ⭐⭐⭐ | 🔧🔧 | V1.2 |
| **3** | Découverte & fuzzing | L3 | ⭐⭐ | 🔧🔧🔧 | V2.0 |
| **4** | Orchestration LangGraph | L4 | ⭐⭐⭐ | 🔧🔧 | V2.0 |
| **5** | Plateforme web pro | L5, L6, L7 | ⭐⭐⭐ | 🔧🔧🔧 | V2.0 |
| **6** | Qualité, benchmark & métriques | L8, L9 | ⭐⭐ | 🔧🔧 | continu |

```mermaid
gantt
    title Plan de route PENTAGON (jalons indicatifs)
    dateFormat YYYY-MM-DD
    axisFormat %b
    section V1.x (quick wins)
    Lot 1 Couverture élargie      :l1, 2026-10-01, 30d
    Lot 2 Exploitation avancée    :l2, after l1, 30d
    section V2.0 (plateforme pro)
    Lot 4 Orchestration LangGraph :l4, after l1, 40d
    Lot 5 Plateforme web pro      :l5, after l2, 55d
    Lot 3 Découverte & fuzzing    :l3, after l4, 40d
    section Continu
    Lot 6 Qualité & métriques     :l6, 2026-10-15, 120d
```

---

## 4. Lot 1 — Couverture élargie (détection)

**Objectif :** ajouter des familles de failles **hors OWASP Top 10 web** et corréler les versions aux CVE, sans nécessiter la catégorie `exploitation`.

**Contenu :**
- **TLS/SSL** : protocoles obsolètes, chiffrements faibles, certificat expiré/auto-signé, HSTS.
- **DNS / e-mail** : SPF/DKIM/DMARC manquants, transfert de zone (AXFR), subdomain takeover.
- **Config HTTP** (extension `security_headers`) : cookies `HttpOnly`/`Secure`/`SameSite`, clickjacking, méthodes HTTP dangereuses.
- **Réseau/services** : analyse enrichie de la sortie Nmap (services exposés, panneaux d'admin).
- **CVE** (L2) : corréler les versions détectées (`whatweb`/`nmap`) à une base CVE.

**Process mis en place — le patron « brancher un nouvel outil » :**

```mermaid
flowchart LR
    NEW["Nouvel outil<br/>(ex. tls_analyzer)"] --> CONTRACT["Contrat commun :<br/>run(...) -> dict normalisé<br/>{findings, severity, evidence}"]
    CONTRACT --> AGENT{"Rattaché à quel agent ?"}
    AGENT -->|passif| OSINT["OSINT"]
    AGENT -->|actif léger| SCAN["Scanning / Web App"]
    OSINT & SCAN --> ROE["Catégorie RoE déclarée<br/>(passive / active_scan)"]
    ROE --> STATE["Alimente l'état partagé"]
    STATE --> LLM["LLM interprète<br/>(impact, priorité)"]
    LLM --> REP["Rapport unifié"]
```

**Workflow d'exécution ajouté (dans les phases existantes) :**

```mermaid
sequenceDiagram
    participant SCAN as Agent Scanning
    participant TLS as tls_analyzer (nouveau)
    participant CVE as cve_matcher (nouveau)
    participant DB as Base CVE (locale/API)
    SCAN->>TLS: analyser TLS de la cible
    TLS-->>SCAN: protocoles/chiffrements/cert
    SCAN->>CVE: versions détectées (whatweb/nmap)
    CVE->>DB: rechercher CVE connues
    DB-->>CVE: liste CVE + scores CVSS
    CVE-->>SCAN: findings enrichis
```

**Livrables :** 4-5 nouveaux outils, mapping RoE, extension du `report_builder` (nouvelles familles), campagne de validation sur Kali.

---

## 5. Lot 2 — Exploitation avancée

**Objectif :** prouver des classes de failles absentes aujourd'hui.

**Contenu :** CSRF, SSRF (A10), SSTI, path traversal / LFI, injection de commande, open redirect ; **tests multi-rôles** (escalade verticale de privilèges).

> **État (avancement) :** ✅ LFI/path traversal, ✅ open redirect, ✅ SSTI
> (A03/CWE-1336, preuve par évaluation d'expression serveur), ✅ SSRF
> (A10/CWE-918, preuve par requête sortante vers un canari), ✅ CSRF
> (A01/CWE-352, preuve par action d'état inter-site sans jeton). Chaque testeur
> est non destructif et branché dans l'agent Exploitation, avec faille
> correspondante semée dans VulnShop. **Reste :** injection de commande,
> tests multi-rôles (escalade verticale).

**Process — cycle « détecter → prouver » étendu (même patron que SQLi/XSS) :**

```mermaid
flowchart LR
    D["Web App détecte<br/>le candidat"] --> SEL{"Classe ?"}
    SEL -->|SSRF| S1["ssrf_tester<br/>(callback OOB contrôlé)"]
    SEL -->|SSTI| S2["ssti_tester<br/>(payload d'évaluation borné)"]
    SEL -->|LFI| S3["lfi_tester<br/>(lecture de fichier témoin)"]
    S1 & S2 & S3 --> P{"Preuve obtenue ?"}
    P -->|Oui| PROVEN["Vulnérabilité PROUVÉE<br/>(non destructive)"]
    P -->|Non| DROP["Écartée"]
```

**Garde-fou maintenu :** chaque testeur reste **non destructif** (preuve minimale : marqueur, lecture d'un fichier témoin, callback OOB neutre) — devise « prouver, jamais ravager ». Catégorie `exploitation` requise + RoE.

**Workflow multi-rôles :**

```mermaid
sequenceDiagram
    participant EXP as Agent Exploitation
    participant AUTH as auth (compte bas privilège)
    participant CIBLE as Cible
    EXP->>AUTH: obtenir token rôle "user"
    EXP->>CIBLE: accéder à une ressource "admin" avec ce token
    alt Accès accordé
        EXP-->>EXP: escalade verticale PROUVÉE
    else Refusé (403)
        EXP-->>EXP: contrôle d'accès OK (pas de faille)
    end
```

---

## 6. Lot 3 — Découverte & fuzzing

**Objectif :** dépasser la surface « statique » (bundle JS + gobuster) et sonder plus profondément.

**Contenu :** crawler applicatif (suivi de liens/formulaires), fuzzing de paramètres, amorce de **chaînage d'exploits**.

**Workflow — boucle de découverte itérative :**

```mermaid
flowchart TB
    SEED["Points d'entrée initiaux<br/>(OSINT + js_analyzer)"] --> CRAWL["Crawler :<br/>suivre liens & formulaires"]
    CRAWL --> NEWURL{"Nouveaux endpoints<br/>découverts ?"}
    NEWURL -->|Oui| ROECHK["Vérif RoE (in-scope ?)"]
    ROECHK -->|autorisé| CRAWL
    NEWURL -->|Non| FUZZ["Fuzzing des paramètres<br/>(mutations bornées)"]
    FUZZ --> SIGNAL{"Signal d'anomalie ?<br/>(erreur, écho, délai)"}
    SIGNAL -->|Oui| HANDOFF["Transmis aux testeurs<br/>ciblés (Lot 2)"]
    SIGNAL -->|Non| STOP["Fin (budget épuisé)"]
```

**Garde-fous :** budget de requêtes plafonné (anti-DoS involontaire, respect WAF), périmètre RoE re-vérifié à chaque nouvel endpoint, pas de mutation destructive.

---

## 7. Lot 4 — Orchestration LangGraph

**Objectif :** remplacer l'orchestrateur séquentiel par une **machine à états** : parallélisme, reprise après incident, boucles conditionnelles.

**Process — de la ligne au graphe :**

```mermaid
stateDiagram-v2
    [*] --> OSINT
    OSINT --> Scanning
    OSINT --> WebApp: en parallèle si RoE OK
    Scanning --> WebApp
    WebApp --> DecisionExploit
    DecisionExploit --> Exploitation: si candidats + exploitation autorisée
    DecisionExploit --> Reporting: sinon
    Exploitation --> ReRecon: si nouvel asset découvert
    ReRecon --> WebApp: boucle conditionnelle
    Exploitation --> Reporting
    Reporting --> [*]
    note right of DecisionExploit
        Checkpointing à chaque
        transition → reprise
        après crash
    end note
```

**Apports concrets :**
- **Parallélisme** : Scanning et Web App lancés en concurrence quand ils sont indépendants.
- **Checkpointing** : l'état est persisté à chaque nœud → une campagne interrompue **reprend** où elle s'est arrêtée.
- **Boucles conditionnelles** : un asset découvert en exploitation peut **relancer** une reconnaissance ciblée (sous contrôle RoE).

**Compatibilité :** le contrat des agents (état partagé) est conservé → migration incrémentale, le RoE Enforcer reste le garde-fou de chaque nœud.

---

## 8. Lot 5 — Plateforme web pro

**Objectif :** transformer l'UI locale en **plateforme multi-utilisateur authentifiée**, persistante, avec file d'attente de campagnes et rapports interactifs. (Prérequis absolu pour « accessible n'importe où ».)

**Architecture cible :**

```mermaid
flowchart TB
    subgraph Front["Front web (opérateurs)"]
        UI["Interface : campagnes,<br/>RoE, résultats, re-test"]
    end
    subgraph Back["Backend API authentifié"]
        AUTH["Auth + RBAC<br/>(rôles opérateur/lecteur)"]
        API["API campagnes"]
        QUEUE["File d'attente"]
        DB["Persistance<br/>(campagnes, findings, audit)"]
    end
    subgraph Workers["Workers d'exécution (Kali)"]
        W1["Worker 1<br/>(Orchestrateur + RoE)"]
        W2["Worker N"]
    end
    UI --> AUTH --> API
    API --> QUEUE --> W1 & W2
    W1 & W2 --> DB
    API --> DB
    DB --> UI
```

**Workflow — cycle de vie d'une campagne (multi-job) :**

```mermaid
sequenceDiagram
    participant OP as Opérateur (authentifié)
    participant API as Backend
    participant Q as File d'attente
    participant W as Worker (Kali)
    participant DB as Base
    OP->>API: créer campagne (URL + RoE)
    API->>DB: enregistrer (statut: en attente)
    API->>Q: enfiler le job
    W->>Q: prendre un job
    W->>W: exécuter (LangGraph + RoE)
    W-->>DB: progression + findings (live)
    DB-->>OP: streaming temps réel
    W->>DB: statut: terminé
    OP->>API: consulter rapport interactif
```

**Workflow — remédiation & re-test (valeur pro clé) :**

```mermaid
flowchart LR
    F["Finding prouvé"] --> ASSIGN["Assigné + statut<br/>(ouvert)"]
    ASSIGN --> FIX["Équipe corrige"]
    FIX --> RETEST["Re-test ciblé<br/>(rejoue le seul testeur concerné)"]
    RETEST --> V{"Toujours exploitable ?"}
    V -->|Oui| ASSIGN
    V -->|Non| CLOSED["Statut : corrigé<br/>(preuve de non-régression)"]
```

**Sécurité de la plateforme :** authentification obligatoire (jamais de console d'attaque ouverte), RBAC, journal d'audit persistant, isolation des workers, scope interactif porté dans l'UI (L6).

---

## 9. Lot 6 — Qualité, benchmark & métriques

**Objectif :** mesurer et fiabiliser (rigueur académique + confiance pro).

**Contenu :** banc d'essai d'applications vulnérables variées (au-delà des cibles maison), **métriques précision/rappel** vs vérité terrain, vérification formelle des findings, CI/CD.

**Workflow — évaluation mesurée :**

```mermaid
flowchart LR
    BENCH["Banc d'apps vulnérables<br/>(vérité terrain connue)"] --> RUN["Campagnes PENTAGON"]
    RUN --> COMPARE["Comparer findings<br/>vs vérité terrain"]
    COMPARE --> METRICS["Précision / Rappel / F1<br/>+ faux positifs/négatifs"]
    METRICS --> REG{"Régression ?"}
    REG -->|Oui| FIX["Corriger outil/prompt"]
    REG -->|Non| REPORT["Rapport de qualité<br/>(pour la soutenance)"]
```

**CI/CD :** tests purs (déjà présents) exécutés automatiquement, non-régression sur le banc, garde-fous de reproductibilité des sorties LLM.

---

## 10. Séquencement recommandé

```mermaid
flowchart LR
    L1["Lot 1<br/>Couverture"] --> L2["Lot 2<br/>Exploitation"]
    L1 --> L4["Lot 4<br/>LangGraph"]
    L2 --> L5["Lot 5<br/>Plateforme"]
    L4 --> L5
    L4 --> L3["Lot 3<br/>Découverte"]
    L6["Lot 6 — Qualité (continu, en parallèle)"] -.accompagne tout.-> L1 & L2 & L3 & L4 & L5
```

**Logique :**
1. **Lot 1** d'abord (quick win, forte valeur soutenance : « au-delà du Top 10 »).
2. **Lot 4** en parallèle (socle technique pour tout le reste).
3. **Lot 2** (profondeur de preuve), puis **Lot 5** (la plateforme, qui a besoin de LangGraph).
4. **Lot 3** ensuite (découverte, la plus coûteuse).
5. **Lot 6** en continu tout du long.

---

## 11. Résumé

| Priorité | Lot | Ce qu'il change concrètement |
|---|---|---|
| 1 | **Lot 1** | Failles hors Top 10 (TLS, DNS/e-mail, config, réseau) + CVE — sans exploitation |
| 2 | **Lot 4** | Orchestrateur → graphe LangGraph : parallèle, reprise, boucles |
| 3 | **Lot 2** | Preuve de CSRF/SSRF/SSTI/LFI + escalade de privilèges |
| 4 | **Lot 5** | Plateforme authentifiée, multi-campagnes, re-test, rapports interactifs |
| 5 | **Lot 3** | Crawler + fuzzing = découverte profonde de la surface |
| — | **Lot 6** | Métriques précision/rappel + CI/CD (en continu) |

**Le Lot 5 (plateforme web pro) est le point d'aboutissement de l'expérience utilisateur** — c'est là que la « directive visuelle de l'expérience web au-delà du CLI » prendra place (à réaliser sur ta demande).
