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
from pentagon.tools.whatweb_tool import run_whatweb_scan
from pentagon.tools.tls_analyzer_tool import run_tls_analysis
from pentagon.tools.network_exposure_tool import analyze_network_exposure
from pentagon.tools.cve_lookup_tool import run_cve_analysis
from pentagon.tools.waf_detector_tool import run_waf_detection
from pentagon.tools.origin_discovery_tool import verify_origin_exposure

SCANNING_SYSTEM_PROMPT = """Tu es l'Agent Scanning & Enumeration de PENTAGON, un système \
multi-agent de test d'intrusion automatisé.

Ton rôle :
- Tu effectues la phase 3 du PTES (Threat Modeling) et le début de la phase 4
- Tu analyses les résultats de scan Nmap (ports/services) et WhatWeb (technologies web) pour identifier la surface d'attaque
- Tu corrèles les deux sources pour reconstituer l'architecture complète de la cible
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
        osint_context: dict[str, Any] | None = None,
        origin_candidates: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Exécute l'agent Scanning sur une cible.

        Args:
            target: cible à scanner (domaine ou IP).
            scan_profile: profil Nmap ("quick", "standard", "web_focused", "full").
            osint_context: contexte transmis par l'agent OSINT.
            origin_candidates: IP d'origine (hors-Cloudflare) déjà AUTORISÉES par
                le RoE, à vérifier activement pour confirmer une exposition
                d'origine. L'orchestrateur ne transmet ici que des IP validées ;
                l'agent ne décide pas du périmètre.

        Returns:
            Dictionnaire structuré avec les résultats de l'agent.
        """
        started_at = datetime.now(timezone.utc)

        print(f"[{self.name}] Démarrage du scan sur '{target}' (profil: {scan_profile})")
        print(f"[{self.name}] ⚠️  Trafic actif émis vers la cible")

        # 1. Exécution du scan Nmap (ports/services)
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

        # 2. Exécution du scan WhatWeb (technologies web)
        # WhatWeb a besoin d'une URL complète (avec https://)
        whatweb_url = target if target.startswith("http") else f"https://{target}"
        print(f"[{self.name}] Invocation de WhatWeb...")
        whatweb_data = run_whatweb_scan(target_url=whatweb_url, aggression="polite")

        if whatweb_data["status"] == "error":
            print(f"[{self.name}] ⚠️  WhatWeb échoué (on continue avec Nmap seul) : {whatweb_data['error']}")

        # 2bis. Analyse de la configuration TLS/SSL (hors OWASP Top 10 web)
        print(f"[{self.name}] Analyse de la configuration TLS/SSL...")
        tls_data = run_tls_analysis(whatweb_url)
        if tls_data.get("status") == "success":
            n_tls = len(tls_data.get("findings", []))
            print(f"[{self.name}]   → {n_tls} finding(s) TLS")
        else:
            print(f"[{self.name}]   → TLS non analysable : {tls_data.get('error')}")

        # 2ter. Analyse de l'exposition réseau (services risqués dans Nmap)
        print(f"[{self.name}] Analyse de l'exposition réseau...")
        net_data = analyze_network_exposure(nmap_data)
        if net_data.get("status") == "success":
            print(f"[{self.name}]   → {len(net_data.get('findings', []))} finding(s) exposition réseau")

        # 2quater. Corrélation CVE (versions détectées → failles connues, OWASP A06)
        print(f"[{self.name}] Corrélation CVE des composants détectés (NVD)...")
        cve_data = run_cve_analysis(whatweb_data, nmap_data)
        print(f"[{self.name}]   → {len(cve_data.get('findings', []))} composant(s) à CVE connues")

        # 2quinquies. Détection de WAF/CDN (identification des couches de défense)
        print(f"[{self.name}] Détection WAF/CDN...")
        waf_data = run_waf_detection(whatweb_url)
        if waf_data.get("is_cloudflare"):
            print(f"[{self.name}] 🛡️  Cloudflare détecté devant la cible")

        # 2sexies. Vérification d'exposition d'origine (seulement sur IP RoE-autorisées)
        origin_verification = self._verify_origins(target, origin_candidates)

        # 3. Analyse corrélée par le LLM
        print(f"[{self.name}] Analyse LLM des résultats du scan...")
        analysis = self._analyze_with_llm(
            target, nmap_data, whatweb_data, tls_data, net_data, cve_data,
            osint_context, waf_data, origin_verification)

        # 4. Construction du résultat final
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
            "tools_used": ["nmap", "whatweb", "tls", "network_exposure", "cve_lookup",
                           "waf_detection", "origin_verification"],
            "raw_data": {
                "nmap": nmap_data,
                "whatweb": whatweb_data,
                "tls": tls_data,
                "network_exposure": net_data,
                "cve_lookup": cve_data,
                "waf_detection": waf_data,
                "origin_verification": origin_verification,
            },
            "analysis": analysis,
        }
        
        # 4. Génération du résumé exécutif
        print(f"[{self.name}] Génération du résumé exécutif...")
        result["executive_summary"] = self.generate_summary(result)
        
        print(f"[{self.name}] Terminé en {duration_seconds:.2f}s")
        return result
    
    def _verify_origins(
        self,
        target: str,
        origin_candidates: list[str] | None,
    ) -> dict[str, Any]:
        """
        Vérifie activement l'exposition des IP d'origine déjà autorisées.

        Ne fait rien si aucune IP n'est fournie (cas nominal : l'opérateur n'a
        pas élargi le périmètre aux origines découvertes). Chaque vérification
        émet du trafic vers l'IP concernée — d'où l'exigence d'une autorisation
        RoE en amont, garantie par l'orchestrateur.
        """
        summary: dict[str, Any] = {
            "checked": [],
            "exposed_origins": [],
            "findings": [],
        }
        if not origin_candidates:
            return summary

        target_host = target.replace("https://", "").replace("http://", "").split("/")[0]

        for ip in origin_candidates:
            print(f"[{self.name}] Vérification d'exposition d'origine sur {ip}...")
            verdict = verify_origin_exposure(ip, target_host)
            summary["checked"].append(ip)
            if verdict.get("exposed"):
                print(f"[{self.name}] 🚨 Origine exposée confirmée : {ip}")
                summary["exposed_origins"].append(ip)
                if verdict.get("finding"):
                    summary["findings"].append(verdict["finding"])
        return summary

    def _analyze_with_llm(
        self,
        target: str,
        nmap_data: dict[str, Any],
        whatweb_data: dict[str, Any],
        tls_data: dict[str, Any] | None = None,
        net_data: dict[str, Any] | None = None,
        cve_data: dict[str, Any] | None = None,
        osint_context: dict[str, Any] | None = None,
        waf_data: dict[str, Any] | None = None,
        origin_verification: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Analyse LLM corrélée : Nmap, WhatWeb, TLS, exposition réseau et CVE.
        """
        current_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Section WAF/origine (couches de défense et exposition éventuelle)
        defense_section = ""
        if waf_data or origin_verification:
            waf_json = json.dumps(waf_data or {}, indent=2, ensure_ascii=False, default=str)
            origin_json = json.dumps(
                origin_verification or {}, indent=2, ensure_ascii=False, default=str
            )
            defense_section = f"""=== DÉTECTION WAF/CDN ===
```json
{waf_json}
```

=== VÉRIFICATION D'EXPOSITION D'ORIGINE ===
```json
{origin_json}
```

Si une origine est marquée `exposed`, c'est un finding de sévérité HIGH \
(contournement du WAF Cloudflare par accès direct à l'IP) : intègre-le à \
`key_findings` et à `defense_layers`.

"""

        # Prépare la section contexte OSINT si disponible
        osint_section = ""
        if osint_context:
            osint_section = f"""=== CONTEXTE OSINT (découvert par l'agent précédent) ===
```json
{json.dumps(osint_context, indent=2, ensure_ascii=False, default=str)}
```

Utilise ce contexte OSINT comme source de vérité confirmée. Par exemple, si \
l'hébergeur a déjà été identifié par l'OSINT, ne le devine pas — utilise l'information confirmée.

"""
        
        tls_block = json.dumps(tls_data or {}, indent=2, ensure_ascii=False,
                               default=str)
        net_block = json.dumps(net_data or {}, indent=2, ensure_ascii=False,
                               default=str)
        cve_block = json.dumps(cve_data or {}, indent=2, ensure_ascii=False,
                               default=str)

        user_prompt = f"""Date actuelle : {current_date}

Analyse les résultats de scan effectués sur la cible '{target}'.

{osint_section}=== DONNÉES NMAP (ports et services) ===
```json
{json.dumps(nmap_data, indent=2, ensure_ascii=False, default=str)}
```

=== DONNÉES WHATWEB (technologies web) ===
```json
{json.dumps(whatweb_data, indent=2, ensure_ascii=False, default=str)}
```

=== DONNÉES TLS/SSL (configuration du transport chiffré) ===
```json
{tls_block}
```

=== EXPOSITION RÉSEAU (services risqués repérés dans Nmap) ===
```json
{net_block}
```
Chaque entrée de 'findings' d'exposition réseau (base de données exposée, RDP/VNC/\
Telnet/FTP, Docker API, SMB/NFS, panneau d'admin) DOIT apparaître dans tes \
'key_findings' avec le type 'exposed_service' et la sévérité fournie — c'est une \
surface d'attaque réseau hors OWASP Top 10 applicatif.

=== CORRÉLATION CVE (composants versionnés → failles connues, OWASP A06) ===
```json
{cve_block}
```
Chaque entrée de 'findings' CVE (composant avec des CVE connues) DOIT apparaître \
dans tes 'key_findings' avec le type 'vulnerable_component', la sévérité fournie et \
les identifiants CVE cités dans la preuve. C'est l'OWASP A06:2021 (composants \
vulnérables/obsolètes).

{defense_section}Produis une analyse de scanning structurée selon le format JSON défini dans tes instructions.

Sois particulièrement attentif à :
- La CORRÉLATION entre Nmap et WhatWeb (ex: Nmap voit Cloudflare sur les ports, WhatWeb confirme via headers)
- L'identification des couches de défense (WAF, CDN, reverse proxy)
- La déduction de l'architecture complète (frontend, backend, hébergement)
- Les signaux d'hébergement révélés par WhatWeb (ex: header rndr-id = Render.com)
- La CONFIGURATION TLS/SSL : chaque entrée de 'findings' TLS (protocole obsolète, \
chiffrement faible, certificat expiré/auto-signé/non concordant) DOIT apparaître dans \
tes 'key_findings' avec le type 'tls_misconfig' et la sévérité fournie. C'est une famille \
de vulnérabilités HORS OWASP Top 10 applicatif (couche transport) — ne l'ignore pas.
- Les implications pour les agents en aval (quels tests applicatifs sont pertinents ?)
- Les anomalies ou expositions sensibles"""
        
        response_text = self.llm.chat(
            system_prompt=SCANNING_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.2,
            max_tokens=4000,
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
        Parse la réponse du LLM en JSON, avec gestion d'erreurs robuste
        et tentative de récupération si le JSON est tronqué.
        """
        text = response_text.strip()
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        
        # Tentative 1 : parsing direct
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # Tentative 2 : récupération d'un JSON tronqué
        # On essaie de fermer proprement les structures ouvertes
        repaired = self._attempt_json_repair(text)
        if repaired is not None:
            repaired["_note"] = "JSON récupéré après troncature (réponse LLM coupée)"
            return repaired
        
        # Échec total : on retourne le texte brut
        return {
            "error": "JSON parsing failed",
            "raw_response": response_text,
        }
    
    def _attempt_json_repair(self, text: str) -> dict[str, Any] | None:
        """
        Tente de réparer un JSON tronqué en fermant les structures ouvertes.
        
        Stratégie : on coupe au dernier objet/élément complet, puis on
        ferme les crochets et accolades restés ouverts.
        """
        import re
        
        # Cherche la dernière accolade fermante d'un élément complet
        # suivie d'une virgule ou d'un retour à la ligne
        last_complete = text.rfind("},")
        if last_complete == -1:
            last_complete = text.rfind("}")
        
        if last_complete == -1:
            return None
        
        # Tronque après le dernier élément complet
        candidate = text[:last_complete + 1]
        
        # Compte les structures ouvertes pour les fermer
        open_braces = candidate.count("{") - candidate.count("}")
        open_brackets = candidate.count("[") - candidate.count("]")
        
        # Ferme les tableaux puis les objets
        candidate += "]" * open_brackets
        candidate += "}" * open_braces
        
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            return None
