# Agent Scanning — Documentation

## Identité

| Attribut | Valeur |
|---|---|
| **Nom** | Scanning_Agent |
| **Version** | 1.0 |
| **Phase PTES** | 3 — Threat Modeling |
| **Tactique MITRE ATT&CK** | TA0007 — Discovery |
| **Techniques** | T1046 (Network Service Discovery), T1018 (Remote System Discovery) |
| **Niveau de risque RoE** | ⚠️ Actif (émet du trafic vers la cible) |
| **Catégorie OWASP WSTG** | INFO-02 (Fingerprint Web Server) |

## Rôle

Cartographier la surface d'attaque exposée par la cible : ports ouverts,
services exposés, versions, technologies, couches défensives.

## Outils mobilisés

| Outil | Source de données | Fichier |
|---|---|---|
| Nmap | Scan réseau actif | `pentagon/tools/nmap_tool.py` |

## Profils de scan disponibles

| Profil | Ports | Description |
|---|---|---|
| `quick` | 8 ports communs | Scan rapide |
| `standard` | 1-1000 | Scan complet 1000 premiers ports |
| `web_focused` | 10 ports web | Scan ciblé web (par défaut) |
| `full` | 1-65535 | Exhaustif (long) |

## Cycle d'exécution

1. Réception de la cible et du profil de scan
2. Vérification implicite RoE (autorisation requise)
3. Exécution de Nmap avec le profil sélectionné
4. Analyse contextuelle par LLM DeepSeek
5. Production d'un finding structuré JSON
6. Génération d'un résumé exécutif lisible

## Évaluation sur la cible TechShop

Cible : `techshop-vuln.rokina-sylla.me`

| Métrique | Valeur |
|---|---|
| Durée d'exécution | ~50-60 secondes |
| Ports ouverts détectés | 4 (80, 443, 8080, 8443) |
| Couche défensive identifiée | Cloudflare (CDN + WAF) |
| Confiance LLM | 0.85 |

## Limites identifiées (v1.0)

- Pas d'accès aux résultats de l'Agent OSINT (peut deviner faux l'hébergeur)
- Pas encore d'énumération de répertoires (Gobuster, ffuf)
- Pas de détection automatique des technologies web (Wappalyzer)
- WAF Cloudflare limite l'efficacité des scans agressifs

## Évolutions prévues

- [ ] Intégration de Gobuster pour énumération de répertoires
- [ ] Intégration de ffuf pour fuzzing rapide
- [ ] Détection technologies web (whatweb / Wappalyzer)
- [ ] Partage d'état avec l'Agent OSINT via LangGraph
- [ ] Migration vers MCP (Model Context Protocol)
- [ ] Implémentation du RoE Enforcer pour validation préalable
