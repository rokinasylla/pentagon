# Rapport qualité PENTAGON — VulnShop

- **Cible** : https://vulnshop.rokina-sylla.me
- **Campagne** : 7807f953-e686-4b29-9183-b9e0c7a48c88
- **Généré le** : 2026-10-15T20:33:14+00:00

## Métriques

| Métrique | Valeur |
|---|---|
| **Rappel** (couverture de la vérité terrain) | **83.3 %** |
| Précision (borne basse) | 93.3 % |
| F1 (borne basse) | 88.0 % |

| Décompte | n |
|---|---|
| Items de vérité terrain | 12 |
| Findings de la campagne | 15 |
| Vrais positifs (TP) | 10 |
| Faux négatifs (FN, manqués) | 2 |
| Findings non catalogués (FP candidats) | 1 |

> La **précision** est une **borne basse** : tout finding non présent au catalogue est compté comme faux positif, alors que certains peuvent être de vraies failles hors périmètre (à qualifier manuellement).

## Couverture par item (vérité terrain)

| Item | OWASP | Attendu | Trouvé | Profondeur OK | Sources |
|---|---|---|---|---|---|
| IDOR / BOLA sur /api/orders/:id | A01 | proven | ✅ | ✅ | detected, proven |
| IDOR / BOLA sur /api/users/:id | A01 | proven | ✅ | ✅ | proven |
| Exposition de données sensibles sans authentification (MD5 + cartes) | A02 | detected | ✅ | ✅ | detected |
| JWT HS256 à secret faible, forgeable | A02 | proven | ✅ | ✅ | proven |
| JWT sans expiration / claim de debug | A02 | proven | ❌ | — | — |
| Injection SQL — contournement d'authentification | A03 | proven | ✅ | ✅ | proven |
| Injection SQL — basée sur erreurs | A03 | proven | ❌ | — | — |
| XSS réfléchi (paramètre q) | A03 | proven | ✅ | ✅ | proven |
| XSS stocké (commentaires) | A03 | proven | ✅ | ✅ | proven |
| Identifiants par défaut (admin/admin123) | A07 | proven | ✅ | ✅ | proven |
| LFI / path traversal (/api/download) | A03 | proven | ✅ | ✅ | proven |
| Redirection ouverte (/api/go) | A01 | proven | ✅ | ✅ | proven |

## Rappel par catégorie OWASP

| OWASP | Trouvés / Total |
|---|---|
| A01 | 3 / 3 |
| A02 | 2 / 3 |
| A03 | 4 / 5 |
| A07 | 1 / 1 |

## Findings non catalogués (à qualifier)

| Finding | Source | OWASP | Endpoint |
|---|---|---|---|
| Absence de Content-Security-Policy et Strict-Transport-Security | detected | A05 | En-têtes HTTP globaux |
