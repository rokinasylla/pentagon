# PENTAGON — Console (front dédié)

Front React + Vite de la console conversationnelle, consommant l'API `/api/v1`
du backend Flask (`webapp.py`). Décision d'architecture : voir **F3** dans
`docs/ROADMAP_CONSOLE_IMPL.md`.

## Développement

Le backend Flask doit tourner sur `http://127.0.0.1:5000` (`python webapp.py`).

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173 (proxifie /api → :5000)
```

Le dev-server proxifie `/api` vers Flask → même origine côté navigateur, le
cookie de session fonctionne sans configuration CORS.

## Build de production

```bash
npm run build      # produit frontend/dist/
```

`dist/` contient des fichiers statiques à servir depuis Flask (un seul
artefact de déploiement, pas de second serveur). Le branchement de `dist/`
dans Flask se fera avec le lot de mise en production.

## Périmètre actuel (Lot UI-1)

- **Connexion** (`/api/v1/login`, `/api/v1/me`, `/api/v1/logout`).
- **Coquille fil + canevas** avec sélection de session (`/api/jobs`).
- **Liste des findings en lecture** (`/api/v1/sessions/:id/findings`) : carte de
  faille avec sévérité, catégorie, OWASP/CWE et **tracker Détecté → Prouvé →
  Confirmé**.
- Pré-prompts et barre de commandes présents mais **inertes** (branchés au Lot UI-2).

## Identité visuelle

La base est **neutre et sobre**. L'habillage (logo, palette, typographie) se
fait dans `src/styles/tokens.css` (variables CSS) et `src/components/Brand.jsx`
(logo), **sans toucher aux composants**. Remplacez-y les valeurs par votre charte.

## Structure

```
src/
  api/client.js          Client HTTP de l'API (/api/v1 + /api/jobs)
  components/
    Brand.jsx            Logo provisoire
    FindingCard.jsx      Carte de faille
    ProofTracker.jsx     Tracker Détecté→Prouvé→Confirmé
  views/
    Login.jsx            Écran de connexion
    Console.jsx          Coquille fil + canevas
  styles/
    tokens.css           Jetons de design (← identité visuelle ici)
    app.css              Styles de base
```
