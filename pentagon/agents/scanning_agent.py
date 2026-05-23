"""
Agent Scanning & Enumeration pour PENTAGON.

Cet agent est le second maillon de la chaîne PENTAGON. Il cartographie
activement la surface d'attaque exposée par la cible (ports, services, versions),
conformément à :
- PTES Phase 3 (Threat Modeling) et début de Phase 4 (Vulnerability Analysis)
- OWASP WSTG-INFO-02 (Fingerprint Web Server)
- MITRE ATT&CK Tactic TA0007 (Discovery) — Techniques T1046, T1018

Outils mobilisés (v1.0) :
- Nmap : scan de ports avec détection de versions de services

Niveau de risque : ACTIF (émet du trafic vers la cible)
Requiert validation RoE avant exécution.
"""

import json
from datetime import datetime, timezone
from typing import Any

from pentagon.core.llm_client import LLMClient
from pentagon.tools.nmap_tool import run_nmap_scan


SCANNING_SYSTEM_PROMPT = """Tu es l'Agent Scanning & Enumeration de PENTAGON, un système \
multi-agent de test d'intrusion automatisé.

Ton rôle :
- Tu effectues la phase 3 du PTES (Threat Modeling) et le début de la phase 4
- Tu analyses les résultats de scan Nmap pour identifier la surface d'attaque
- Tu identifies les services exposés, leurs versions, et leurs implications de sécurité
- Tu mappes tes observations à MITRE ATT&CK (tactique TA0007 - Discovery)
- Tu rappelles que tes actions sont actives et tracées

Ton style d'analyse :
- Tu es factuel et précis sur les services détectés
- Tu identifies les technologies derrière les ports (Cloudflare, nginx, Apache, etc.)
- Tu signales les anomalies (ports inhabituels, versions obsolètes, configurations exposées)
- Tu déduis l'architecture (reverse proxy, CDN, WAF, load balancer) à partir des indices
- Tu prépares le travail des agents en aval (Web App, Vuln Analysis)

Format de réponse :
Tu réponds toujours en JSON valide, avec la structure suivante :
{
  "summary": "résumé en 2-3 phrases de la surface d'attaque détectée",
  "key_findings": [
    {
      "type": "type (ex: open_port, service_version, technology, anomaly, defense_layer)",
      "value": "valeur observée",
      "significance": "implication de sécurité",
      "attack_mapping": "technique MITRE ATT&CK (ex: T1046)",
      "severity": "info | low | medium | high"
    }
  ],
  "attack_surface": {
    "exposed_ports": [{"port": 80, "service": "http", "version": "..."}],
    "detected_technologies": ["liste des technos identifiées"],
    "defense_layers": ["WAF, CDN, reverse proxy détectés"],
    "architecture_inference": "déduction sur l'architecture (ex: PaaS derrière CDN)"
  },
  "recommendations_for_next_agents": [
    "recommandation pour l'Agent Web App ou Vuln Analysis"
  ],
  "confidence": 0.0
}
"""


SCANNING_SUMMARY_SYSTEM_PROMPT = """Tu es un assistant qui produit des résumés exécutifs pour des \
pentesters et auditeurs de sécurité.

Ton rôle : transformer une analyse de scan technique détaillée en un résumé clair, court et \
exploitable, lisible en moins de 60 secondes.

Format de réponse :
- Texte en français, lisible, professionnel
- Maximum 200 mots
- Structure obligatoire :

🎯 SURFACE D'ATTAQUE
[1-2 phrases qui décrivent ce qui est exposé]

🟢 PORTS ET SERVICES
[Liste courte des ports ouverts et services détectés]

🛡️ DÉFENSES IDENTIFIÉES
[WAF, CDN, reverse proxy détectés — ce qui protège la cible]

🔍 OBSERVATIONS CLÉS
[2-3 puces : technologies identifiées, architecture déduite]

⚠️ POINTS D'ATTENTION
[1-2 puces : anomalies, versions obsolètes, expositions inhabituelles]

➡️ RECOMMANDATIONS PRIORITAIRES
[2-3 actions à mener par les agents suivants]

Pas de jargon excessif. Sois direct et actionnable."""


class ScanningAgent:
    """
    Agent Scanning v1.0 pour PENTAGON.
    
    Cette version utilise Nmap avec différents profils de scan.
    Les versions futures intégreront Gobuster, ffuf, et la détection
    avancée de technologies web (Wappalyzer-like).
    """
    
    def __init__(self, llm: LLMClient | None = None):
        """
        Initialise l'agent Scanning.
        
        Args:
            llm: client LLM à utiliser. Si None, en crée un nouveau.
        """
        self.llm = llm or LLMClient()
        self.name = "Scanning_Agent"
        self.version = "1.0"
        self.ptes_phase = 3
        self.attack_tactic = "TA0007"
        self.risk_level = "active"  # important pour les RoE
    
    def run(
        self,
        target: str,
        scan_profile: str = "web_focused",
    ) -> dict[str, Any]:
        """
        Exécute l'agent Scanning sur une cible.
        
        Args:
            target: cible à scanner (domaine ou IP).
            scan_profile: profil Nmap ("quick", "standard", "web_focused", "full").
        
        Returns:
            Dictionnaire structuré avec les résultats de l'agent.
        """
        started_at = datetime.now(timezone.utc)
        
        print(f"[{self.name}] Démarrage du scan sur '{target}' (profil: {scan_profile})")
        print(f"[{self.name}] ⚠️  Trafic actif émis vers la cible")
        
        # 1. Exécution du scan Nmap
        print(f"[{self.name}] Invocation de Nmap...")
        nmap_data = run_nmap_scan(target=target, profile=scan_profile)
        
        if nmap_data["status"] == "error":
            print(f"[{self.name}] ❌ Scan Nmap échoué : {nmap_data['error']}")
            return {
                "agent": self.name,
                "status": "error",
                "target": target,
                "error": nmap_data["error"],
            }
        
        # 2. Analyse par le LLM
        print(f"[{self.name}] Analyse LLM des résultats du scan...")
        analysis = self._analyze_with_llm(target, nmap_data)
        
        # 3. Construction du résultat final
        ended_at = datetime.now(timezone.utc)
        duration_seconds = (ended_at - started_at).total_seconds()
        
        result = {
            "agent": self.name,
            "version": self.version,
            "ptes_phase": self.ptes_phase,
            "attack_tactic": self.attack_tactic,
            "risk_level": self.risk_level,
            "target": target,
            "scan_profile": scan_profile,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_seconds": duration_seconds,
            "tools_used": ["nmap"],
            "raw_data": {
                "nmap": nmap_data,
            },
            "analysis": analysis,
        }
        
        # 4. Génération du résumé exécutif
        print(f"[{self.name}] Génération du résumé exécutif...")
        result["executive_summary"] = self.generate_summary(result)
        
        print(f"[{self.name}] Terminé en {duration_seconds:.2f}s")
        return result
    
    def _analyze_with_llm(
        self,
        target: str,
        nmap_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Demande au LLM d'analyser les résultats du scan Nmap.
        """
        current_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        
        user_prompt = f"""Date actuelle : {current_date}

Analyse les résultats du scan Nmap effectué sur la cible '{target}'.

=== DONNÉES NMAP ===
```json
{json.dumps(nmap_data, indent=2, ensure_ascii=False, default=str)}
```

Produis une analyse de scanning structurée selon le format JSON défini dans tes instructions.

Sois particulièrement attentif à :
- L'identification des couches de défense (WAF, CDN, reverse proxy)
- La déduction de l'architecture (ex: application derrière Cloudflare, hébergée sur PaaS)
- Les implications pour les agents en aval (quels tests applicatifs sont pertinents ?)
- Les anomalies (ports inhabituels, services obsolètes)"""
        
        response_text = self.llm.chat(
            system_prompt=SCANNING_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.2,
            max_tokens=2000,
        )
        
        return self._parse_llm_response(response_text)
    
    def generate_summary(self, result: dict[str, Any]) -> str:
        """
        Génère un résumé exécutif lisible pour humain.
        """
        analysis = result.get("analysis", {})
        target = result.get("target", "cible inconnue")
        duration = result.get("duration_seconds", 0)
        profile = result.get("scan_profile", "?")
        
        user_prompt = f"""Voici l'analyse de scanning technique complète d'une mission.

Cible : {target}
Profil de scan : {profile}
Durée d'exécution : {duration:.1f} secondes

=== ANALYSE TECHNIQUE COMPLÈTE ===
```json
{json.dumps(analysis, indent=2, ensure_ascii=False, default=str)}
```

Produis le résumé exécutif selon le format défini dans tes instructions."""
        
        summary = self.llm.chat(
            system_prompt=SCANNING_SUMMARY_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.3,
            max_tokens=600,
        )
        
        return summary.strip()
    
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
