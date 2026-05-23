"""
Agent OSINT & Reconnaissance pour PENTAGON.

Cet agent est le premier maillon de la chaîne PENTAGON. Il collecte
passivement des informations publiques sur la cible, conformément à :
- PTES Phase 2 (Intelligence Gathering)
- OWASP WSTG Section INFO
- MITRE ATT&CK Tactic TA0043 (Reconnaissance)

Outils mobilisés (v1.1) :
- WHOIS : informations d'enregistrement du domaine
- DNS Lookup : enregistrements DNS (A, MX, NS, TXT, CNAME)

Niveau de risque : passif (aucune interaction active avec la cible)
"""

import json
from datetime import datetime, timezone
from typing import Any

from pentagon.core.llm_client import LLMClient
from pentagon.tools.whois_tool import run_whois
from pentagon.tools.dns_tool import run_dns_lookup


OSINT_SYSTEM_PROMPT = """Tu es l'Agent OSINT (Open-Source Intelligence) de PENTAGON, un système \
multi-agent de test d'intrusion automatisé.

Ton rôle :
- Tu effectues la phase 2 du PTES (Intelligence Gathering)
- Tu collectes UNIQUEMENT des informations publiques et passives
- Tu ne mènes JAMAIS d'action active vers la cible
- Tu mappes tes observations à MITRE ATT&CK (tactique TA0043) et OWASP WSTG

Ton style d'analyse :
- Tu es factuel et précis
- Tu corrèles les informations issues de plusieurs sources (WHOIS, DNS)
- Tu identifies les informations utiles pour les phases suivantes du pentest
- Tu signales les anomalies ou points d'intérêt (privacy services, hébergeurs, configurations inhabituelles)
- Tu structures tes findings de manière exploitable par les agents en aval

Format de réponse :
Tu réponds toujours en JSON valide, avec la structure suivante :
{
  "summary": "résumé en 2-3 phrases de ce que tu as appris sur la cible",
  "key_findings": [
    {
      "type": "type de finding (ex: registrar, infrastructure, hosting, dns, anomaly)",
      "value": "valeur observée",
      "significance": "pourquoi c'est important pour la suite du pentest",
      "attack_mapping": "technique MITRE ATT&CK correspondante (ex: T1590.002)",
      "source_tool": "outil source (whois ou dns)"
    }
  ],
  "infrastructure_summary": {
    "hosting_provider": "hébergeur identifié si applicable",
    "ip_addresses": ["liste des IP révélées"],
    "name_servers": ["liste des serveurs DNS"],
    "mail_servers": ["liste des serveurs mail si applicable"]
  },
  "recommendations_for_next_agents": [
    "recommandation 1 pour l'Agent Scanning ou Web App"
  ],
  "confidence": 0.0
}
"""
OSINT_SUMMARY_SYSTEM_PROMPT = """Tu es un assistant qui produit des résumés exécutifs pour des \
pentesters et auditeurs de sécurité.

Ton rôle : transformer une analyse OSINT technique détaillée en un résumé clair, court et \
exploitable, lisible en moins de 60 secondes.

Format de réponse :
- Texte en français, lisible, professionnel
- Maximum 200 mots
- Structure obligatoire :

🎯 CIBLE
[1 phrase qui décrit la cible et son contexte]

🏗️ INFRASTRUCTURE
[3-4 puces courtes : hébergeur, IPs, particularités techniques]

🔍 OBSERVATIONS CLÉS
[2-3 puces courtes : éléments les plus importants pour la suite]

⚠️ POINTS D'ATTENTION
[1-2 puces courtes : anomalies, risques, choses à vérifier]

➡️ RECOMMANDATIONS PRIORITAIRES
[2-3 actions à mener par les agents suivants, formulées brièvement]

Pas de jargon excessif. Pas de mapping ATT&CK dans le résumé (réservé au rapport détaillé).
Sois direct et actionnable."""

class OSINTAgent:
    """
    Agent OSINT v1.1 pour PENTAGON.
    
    Cette version utilise :
    - L'outil WHOIS pour les informations d'enregistrement
    - L'outil DNS Lookup pour les enregistrements DNS
    
    Les versions futures intégreront theHarvester, recherche de fuites GitHub, etc.
    """
    
    def __init__(self, llm: LLMClient | None = None):
        """
        Initialise l'agent OSINT.
        
        Args:
            llm: client LLM à utiliser. Si None, en crée un nouveau.
        """
        self.llm = llm or LLMClient()
        self.name = "OSINT_Agent"
        self.version = "1.1"
        self.ptes_phase = 2
        self.attack_tactic = "TA0043"
    
    def run(self, target_domain: str) -> dict[str, Any]:
        """
        Exécute l'agent OSINT sur une cible.
        
        Args:
            target_domain: domaine cible (ex: "techshop-vuln.rokina-sylla.me")
        
        Returns:
            Un dictionnaire structuré avec les résultats de l'agent.
        """
        started_at = datetime.now(timezone.utc)
        
        print(f"[{self.name}] Démarrage de la reconnaissance sur '{target_domain}'")
        
        # 1. Collecte WHOIS
        print(f"[{self.name}] Invocation de l'outil WHOIS...")
        whois_data = run_whois(target_domain)
        
        # 2. Collecte DNS
        print(f"[{self.name}] Invocation de l'outil DNS Lookup...")
        dns_data = run_dns_lookup(target_domain)
        
        # 3. Analyse corrélée par le LLM
        print(f"[{self.name}] Analyse LLM des données collectées...")
        analysis = self._analyze_with_llm(target_domain, whois_data, dns_data)
        
        # 4. Construction du résultat final structuré
        ended_at = datetime.now(timezone.utc)
        duration_seconds = (ended_at - started_at).total_seconds()
        
        result = {
            "agent": self.name,
            "version": self.version,
            "ptes_phase": self.ptes_phase,
            "attack_tactic": self.attack_tactic,
            "target": target_domain,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_seconds": duration_seconds,
            "tools_used": ["whois", "dns_lookup"],
            "raw_data": {
                "whois": whois_data,
                "dns": dns_data,
            },
            "analysis": analysis,
        }
        
        # Génère le résumé exécutif humain-friendly
        print(f"[{self.name}] Génération du résumé exécutif...")
        result["executive_summary"] = self.generate_summary(result)
        
        print(f"[{self.name}] Terminé en {duration_seconds:.2f}s")
        return result
    
    def _analyze_with_llm(
        self,
        target: str,
        whois_data: dict[str, Any],
        dns_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Demande au LLM d'analyser les données collectées (WHOIS + DNS).
        """
        current_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        
        user_prompt = f"""Date actuelle : {current_date}

Analyse les données de reconnaissance collectées sur la cible '{target}'.

=== DONNÉES WHOIS ===
```json
{json.dumps(whois_data, indent=2, default=str)}
```

=== DONNÉES DNS ===
```json
{json.dumps(dns_data, indent=2, default=str)}
```

Produis une analyse OSINT corrélée et structurée selon le format JSON défini dans tes instructions.
Identifie les éléments utiles pour les phases suivantes du pentest (Scanning, Web App Testing, \
Vulnerability Analysis). Sois particulièrement attentif aux corrélations entre WHOIS et DNS \
(ex: hébergeur identifié via CNAME mais privacy service activé sur WHOIS)."""
        
        response_text = self.llm.chat(
            system_prompt=OSINT_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.2,
            max_tokens=2000,
        )
        
        return self._parse_llm_response(response_text)
    
    def _parse_llm_response(self, response_text: str) -> dict[str, Any]:
        """
        Parse la réponse du LLM en JSON, avec gestion d'erreurs robuste.
        """
        text = response_text.strip()
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            return {
                "error": f"JSON parsing failed: {e}",
                "raw_response": response_text,
            }
    def generate_summary(self, result: dict[str, Any]) -> str:
        """
        Génère un résumé exécutif lisible pour un humain à partir du résultat brut.
        
        Cette méthode prend l'output complet de `run()` et demande au LLM
        de produire un résumé court et exploitable, adapté à une lecture rapide
        par un pentester ou un auditeur.
        
        Args:
            result: dict complet retourné par self.run()
        
        Returns:
            Un texte en français formaté pour affichage console.
        """
        analysis = result.get("analysis", {})
        target = result.get("target", "cible inconnue")
        duration = result.get("duration_seconds", 0)
        
        user_prompt = f"""Voici l'analyse OSINT technique complète d'une mission de reconnaissance.

Cible : {target}
Durée d'exécution : {duration:.1f} secondes

=== ANALYSE TECHNIQUE COMPLÈTE ===
```json
{json.dumps(analysis, indent=2, ensure_ascii=False, default=str)}
```

Produis le résumé exécutif selon le format défini dans tes instructions."""
        
        summary = self.llm.chat(
            system_prompt=OSINT_SUMMARY_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.3,
            max_tokens=600,
        )
        
        return summary.strip()
