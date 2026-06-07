"""
Agent Web App pour PENTAGON.

Troisième maillon de la chaîne PENTAGON. Teste l'application web cible
selon la méthodologie OWASP pour détecter les vulnérabilités applicatives.

Conçu pour être GÉNÉRIQUE : découvre dynamiquement la structure de toute
application web (SPA ou serveur) et applique des tests universels.

Conforme à :
- PTES Phase 4 (Vulnerability Analysis)
- OWASP WSTG v4.2 (Web Security Testing Guide)
- OWASP Top 10 2021
- MITRE ATT&CK T1190 (Exploit Public-Facing Application)

Outils mobilisés :
- js_analyzer : découverte d'endpoints via analyse du bundle JS
- api_prober : test de contrôle d'accès et exposition de données
- security_headers : analyse de la configuration de sécurité

Niveau de risque : ACTIF (envoie des requêtes vers la cible)
"""

import json
from datetime import datetime, timezone
from typing import Any

from pentagon.core.llm_client import LLMClient
from pentagon.tools.js_analyzer_tool import run_js_analysis
from pentagon.tools.api_prober_tool import run_api_probe
from pentagon.tools.security_headers_tool import run_security_headers_scan
from pentagon.tools.data_analyzer_tool import run_data_analysis

WEBAPP_SYSTEM_PROMPT = """Tu es l'Agent Web App de PENTAGON, un système multi-agent \
de test d'intrusion automatisé.

Ton rôle :
- Tu effectues la phase 4 du PTES (Vulnerability Analysis) sur les applications web
- Tu analyses les résultats de plusieurs outils pour identifier les vulnérabilités réelles
- Tu suis la méthodologie OWASP WSTG v4.2 et classes selon l'OWASP Top 10 2021
- Tu mappes tes findings à MITRE ATT&CK et CWE

Ton expertise critique — DISTINGUER les vraies vulnérabilités des comportements normaux :
- Un catalogue de produits public (ex: /products) est NORMAL, pas une vulnérabilité
- Une liste d'utilisateurs avec mots de passe accessible sans authentification est CRITIQUE
- L'exposition de mots de passe, cartes bancaires, tokens est TOUJOURS critique
- Des hashes courts (32 caractères hexadécimaux) indiquent du MD5 (faible)
- L'absence de headers de sécurité est une misconfiguration mais rarement critique seule

Tu juges chaque finding dans son CONTEXTE métier, tu ne signales pas tout aveuglément.

Format de réponse :
Tu réponds toujours en JSON valide :
{
  "summary": "résumé en 2-3 phrases de la posture de sécurité de l'application",
  "vulnerabilities": [
    {
      "title": "titre court de la vulnérabilité",
      "severity": "critical | high | medium | low | info",
      "owasp_top10": "ex: A01:2021 Broken Access Control",
      "cwe": "ex: CWE-862",
      "affected_endpoint": "endpoint ou composant concerné",
      "description": "description technique du problème",
      "evidence": "preuve observée (sans données sensibles brutes)",
      "remediation": "recommandation de correction",
      "confidence": 0.0
    }
  ],
  "false_positives_filtered": ["liste des comportements normaux écartés (ex: catalogue public)"],
  "attack_surface_summary": {
    "endpoints_discovered": 0,
    "endpoints_accessible_without_auth": 0,
    "backend_architecture": "description de l'architecture détectée"
  },
  "recommendations_for_next_agents": ["recommandations pour l'agent Exploitation"],
  "overall_risk": "critical | high | medium | low",
  "confidence": 0.0
}

IMPORTANT : ne mets JAMAIS de mots de passe, numéros de carte ou tokens réels \
dans ton rapport. Décris-les ("hash MD5 exposé", "numéro de carte présent") sans les copier."""


WEBAPP_SUMMARY_SYSTEM_PROMPT = """Tu produis un résumé exécutif court et lisible \
d'une analyse de sécurité d'application web, pour un pentester ou un auditeur.

Format (maximum 200 mots) :

🎯 APPLICATION
[1-2 phrases : type d'app, architecture]

🔴 VULNÉRABILITÉS CRITIQUES
[Les findings critical/high, formulés brièvement. Si aucun, écrire "Aucune vulnérabilité critique."]

🟠 PROBLÈMES SECONDAIRES
[Les findings medium/low, en une ligne chacun]

✅ POINTS POSITIFS
[Ce qui est bien configuré, le cas échéant]

➡️ ACTIONS PRIORITAIRES
[2-3 recommandations concrètes]

Ne mets jamais de données sensibles réelles (mots de passe, cartes) dans le résumé."""


class WebAppAgent:
    """
    Agent Web App v1.0 pour PENTAGON.
    
    Orchestre l'analyse JS, le sondage d'API et l'analyse des headers,
    puis fait juger le contexte par le LLM.
    """
    
    def __init__(self, llm: LLMClient | None = None):
        self.llm = llm or LLMClient()
        self.name = "WebApp_Agent"
        self.version = "1.0"
        self.ptes_phase = 4
        self.attack_technique = "T1190"
        self.risk_level = "active"
    
    def run(
        self,
        target: str,
        osint_context: dict[str, Any] | None = None,
        scanning_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Exécute l'agent Web App sur une cible.
        
        Args:
            target: URL ou domaine de la cible.
            osint_context: contexte des agents précédents (optionnel).
            scanning_context: contexte de l'agent scanning (optionnel).
        
        Returns:
            Dictionnaire structuré avec les résultats.
        """
        started_at = datetime.now(timezone.utc)
        
        # Normalise l'URL
        target_url = target if target.startswith("http") else f"https://{target}"
        
        print(f"[{self.name}] Démarrage de l'analyse web sur '{target_url}'")
        print(f"[{self.name}] ⚠️  Trafic actif émis vers la cible")
        
        # === Outil 1 : Analyse du bundle JS (découverte) ===
        print(f"[{self.name}] Analyse du bundle JavaScript...")
        js_data = run_js_analysis(target_url)
        
        # Détermine où tester l'API : backend découplé ou cible directe
        backend_urls = js_data.get("backend_urls", [])
        if backend_urls:
            api_base = backend_urls[0]
            print(f"[{self.name}] Backend découplé détecté : {api_base}")
        else:
            api_base = target_url
            print(f"[{self.name}] Pas de backend séparé, test direct sur la cible")
        
        # Endpoints à tester = routes découvertes
        endpoints_to_test = js_data.get("app_routes", [])
        
        # === Outil 2 : Sondage des endpoints ===
        print(f"[{self.name}] Sondage de {len(endpoints_to_test)} endpoints...")
        api_data = run_api_probe(base_url=api_base, endpoints=endpoints_to_test)
        
        # === Outil 3 : Analyse des headers de sécurité ===
        print(f"[{self.name}] Analyse des headers de sécurité...")
        headers_data = run_security_headers_scan(target_url)
        # === Outil 4 : Analyse approfondie des données exposées ===
        # Analyse les données JSON récupérées par l'api_prober pour détecter
        # hashes faibles, mots de passe cassables, cartes bancaires.
        print(f"[{self.name}] Analyse approfondie des données exposées...")
        data_analysis_results = []
        for endpoint_result in api_data.get("results", []):
            raw_data = endpoint_result.get("raw_json_data")
            if raw_data:
                analysis = run_data_analysis(raw_data)
                if analysis.get("findings"):
                    data_analysis_results.append({
                        "endpoint": endpoint_result["endpoint"],
                        "url": endpoint_result["url"],
                        "analysis": analysis,
                    })
        
        if data_analysis_results:
            total_cracked = sum(
                len(d["analysis"]["cracked_passwords"]) for d in data_analysis_results
            )
            print(f"[{self.name}]   → {len(data_analysis_results)} endpoint(s) avec données sensibles analysées")
            if total_cracked:
                print(f"[{self.name}]   → ⚠️  {total_cracked} mot(s) de passe cassé(s)")
        # === Analyse LLM contextuelle ===
        print(f"[{self.name}] Analyse LLM des résultats...")
        analysis = self._analyze_with_llm(
            target_url, js_data, api_data, headers_data,
            data_analysis_results,  osint_context, scanning_context,
        )
        
        # === Construction du résultat ===
        ended_at = datetime.now(timezone.utc)
        duration = (ended_at - started_at).total_seconds()
        
        result = {
            "agent": self.name,
            "version": self.version,
            "ptes_phase": self.ptes_phase,
            "attack_technique": self.attack_technique,
            "risk_level": self.risk_level,
            "target": target_url,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_seconds": duration,
            "tools_used": ["js_analyzer", "api_prober", "security_headers", "data_analyzer"],
            "raw_data": {
                "js_analysis": js_data,
                "api_probe": api_data,
                "security_headers": headers_data,
                "data_analysis": data_analysis_results,
            },
            "analysis": analysis,
        }
        
        # === Résumé exécutif ===
        print(f"[{self.name}] Génération du résumé exécutif...")
        result["executive_summary"] = self.generate_summary(result)
        
        print(f"[{self.name}] Terminé en {duration:.2f}s")
        return result
    
    def _analyze_with_llm(
        self,
        target: str,
        js_data: dict[str, Any],
        api_data: dict[str, Any],
        headers_data: dict[str, Any],
        data_analysis_results: list[dict[str, Any]],
        osint_context: dict[str, Any] | None,
        scanning_context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Analyse contextuelle des résultats des 3 outils par le LLM."""
        current_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        
        # Contexte des agents précédents (si fourni par l'orchestrateur)
        context_section = ""
        if osint_context or scanning_context:
            context_section = "=== CONTEXTE DES AGENTS PRÉCÉDENTS ===\n"
            if osint_context:
                context_section += f"OSINT : {json.dumps(osint_context, ensure_ascii=False, default=str)[:500]}\n"
            if scanning_context:
                context_section += f"Scanning : {json.dumps(scanning_context, ensure_ascii=False, default=str)[:500]}\n"
            context_section += "\n"
        
        user_prompt = f"""Date actuelle : {current_date}

Analyse la sécurité de l'application web '{target}' à partir des résultats de trois outils.

{context_section}=== ANALYSE DU BUNDLE JS (découverte d'endpoints) ===
```json
{json.dumps(js_data, indent=2, ensure_ascii=False, default=str)}
```

=== SONDAGE DES ENDPOINTS (test de contrôle d'accès) ===
```json
{json.dumps(api_data, indent=2, ensure_ascii=False, default=str)}
```

=== ANALYSE DES HEADERS DE SÉCURITÉ ===
```json
{json.dumps(headers_data, indent=2, ensure_ascii=False, default=str)}
```
=== ANALYSE APPROFONDIE DES DONNÉES EXPOSÉES (hashes, mots de passe, cartes) ===
```json
{json.dumps(data_analysis_results, indent=2, ensure_ascii=False, default=str)}
```

Produis une analyse de sécurité structurée selon le format JSON défini dans tes instructions.

RAPPEL CRITIQUE :
- Distingue les vraies vulnérabilités des comportements normaux (un catalogue public n'est PAS une vulnérabilité)
- L'exposition de mots de passe, cartes bancaires ou tokens sans authentification est TOUJOURS critique
- Juge chaque finding dans son contexte métier
- Ne copie JAMAIS de données sensibles réelles dans ton rapport"""
        
        response_text = self.llm.chat(
            system_prompt=WEBAPP_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.2,
            max_tokens=4000,
        )
        
        return self._parse_llm_response(response_text)
    
    def generate_summary(self, result: dict[str, Any]) -> str:
        """Génère un résumé exécutif lisible."""
        analysis = result.get("analysis", {})
        target = result.get("target", "cible inconnue")
        
        user_prompt = f"""Analyse de sécurité web de la cible {target}.

=== ANALYSE COMPLÈTE ===
```json
{json.dumps(analysis, indent=2, ensure_ascii=False, default=str)}
```

Produis le résumé exécutif selon le format défini dans tes instructions."""
        
        summary = self.llm.chat(
            system_prompt=WEBAPP_SUMMARY_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.3,
            max_tokens=800,
        )
        return summary.strip()
    
    def _parse_llm_response(self, response_text: str) -> dict[str, Any]:
        """Parse la réponse JSON du LLM avec récupération de troncature."""
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
        except json.JSONDecodeError:
            pass
        
        # Récupération de JSON tronqué
        repaired = self._attempt_json_repair(text)
        if repaired is not None:
            repaired["_note"] = "JSON récupéré après troncature"
            return repaired
        
        return {"error": "JSON parsing failed", "raw_response": response_text}
    
    def _attempt_json_repair(self, text: str) -> dict[str, Any] | None:
        """Tente de réparer un JSON tronqué en fermant les structures ouvertes."""
        last_complete = text.rfind("},")
        if last_complete == -1:
            last_complete = text.rfind("}")
        if last_complete == -1:
            return None
        
        candidate = text[:last_complete + 1]
        open_braces = candidate.count("{") - candidate.count("}")
        open_brackets = candidate.count("[") - candidate.count("]")
        candidate += "]" * open_brackets
        candidate += "}" * open_braces
        
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            return None
