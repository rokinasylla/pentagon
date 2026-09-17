# VulnShop — 2ᵉ cible d'entraînement pour PENTAGON

Application web **volontairement vulnérable** (Node/Express + SPA + SQLite),
conçue comme **seconde cible** pour démontrer que PENTAGON est **générique**
(qu'il ne fonctionne pas uniquement sur TechShop). Stack Node/JS différente de
la stack Java/Spring de TechShop → preuve de généricité.

> ⚠️ **Usage strictement pédagogique.** Toutes les données sont **factices**
> (faux utilisateurs, numéros de carte de *test*). N'hébergez ceci que pour
> tester **votre propre** outil. C'est une app réellement faillible : ne la
> laissez pas tourner indéfiniment, supprimez le service après vos démos.

## Vulnérabilités semées (objectif : 7/7 OWASP, comme TechShop)

| OWASP | Vulnérabilité | Où |
|-------|---------------|-----|
| A07 | Identifiants par défaut (`admin` / `admin123`) | `POST /api/auth/login` |
| A07/A02 | JWT HS256 à **secret faible** (`secret`) → forgeable, `role` exposé, pas d'`exp` | token de login |
| A03 | **SQLi** contournement d'auth (login concaténé) | `POST /api/auth/login` |
| A03 | **SQLi** basée erreurs (paramètre `q`) | `GET /api/products/search?q=` |
| A01 | **IDOR/BOLA** sur commandes et utilisateurs | `GET /api/orders/:id`, `/api/users/:id` |
| A01/A02 | Contrôle d'accès cassé + **MD5** + « cartes » exposées | `GET /users`, `/orders` |
| A03 | **XSS stocké** (commentaires rendus sans échappement) | `POST /api/comments` + SPA |

Comptes de démonstration (données factices) : `admin/admin123`, `alice/password`,
`bob/123456`, `carol/qwerty`.

## Déploiement en ligne (Render)

1. Pousser ce dossier dans un dépôt GitHub (il est déjà sous
   `targets/vulnshop/` du dépôt PENTAGON — c'est parfait, `render.yaml` pointe
   dessus via `rootDir`).
2. Sur [render.com](https://render.com) : **New → Blueprint**, sélectionner le
   dépôt. Render lit `render.yaml` et crée un service web **gratuit**.
   - *(ou manuellement : New → Web Service, Root Directory `targets/vulnshop`,
     Build `npm install`, Start `node server.js`.)*
3. Render fournit une URL publique https, ex. `https://vulnshop.onrender.com`.
4. **Réveiller le service** avant un test : le free tier s'endort après
   inactivité (premier appel ~50 s). Ouvrez l'URL une fois dans le navigateur.

## Lancer PENTAGON sur cette cible (depuis Kali)

```bash
python pentagon.py \
  --target https://vulnshop.onrender.com \
  --actions passive,active_scan,exploitation \
  --operator rokhaya --yes --report
```

> `exploitation` doit être **explicitement** autorisé (deny-by-default). Le
> `--report` génère le PDF en fin de campagne.

### Confirmer le XSS stocké par navigateur (comme TechShop)

```bash
FRONTEND=https://vulnshop.onrender.com python tests/test_vulnshop_xss_stored_ui.py
```

## Test en local (optionnel)

```bash
cd targets/vulnshop
npm install
npm start          # http://localhost:3000
```

Puis pointer PENTAGON sur `http://localhost:3000`.
