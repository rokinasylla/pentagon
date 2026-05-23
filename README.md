# PENTAGON

**Pen**etration **T**esting **A**gent-based **G**eneric **O**rchestration **N**etwork

Système multi-agent pour le test d'intrusion automatisé, basé sur des LLMs et conforme aux standards méthodologiques PTES, OWASP WSTG, NIST SP 800-115 et MITRE ATT&CK.

## Mémoire de Master 2

Université Alioune Diop de Bambey (UADB) — Systèmes et Réseaux  
Auteur : Ndeye Rokhaya Sylla  
Encadrant : Dr. Lam  
Année : 2025-2026

## Installation

```bash
git clone <repo>
cd pentagon
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows
pip install -r requirements.txt
cp .env.example .env
# éditer .env avec votre clé DeepSeek
```

## Architecture

Le système est organisé en 5 couches :
- Présentation
- Gouvernance et orchestration
- Agents spécialisés (6 agents)
- Outils standardisés (MCP)
- Données et connaissances

Voir `docs/architecture.md` pour les détails.

## Statut du projet

🚧 En cours de développement (Janvier 2026)
