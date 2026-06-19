"""
Orchestrateur séquentiel de PENTAGON (v1).

Cet orchestrateur enchaîne les agents dans l'ordre des phases PTES,
en propageant l'état partagé (PentagonState) entre eux. Chaque agent
enrichit l'état avec ses découvertes, que les agents en aval peuvent
exploiter.

Cette version est un orchestrateur séquentiel simple. Elle sera migrée
vers une machine à états LangGraph (avec checkpointing, transitions
conditionnelles et exécution parallèle) dans une version ultérieure.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any

from pentagon.core.state import PentagonState
from pentagon.core.llm_client import LLMClient
from pentagon.agents.osint_agent import OSINTAgent
from pentagon.agents.scanning_agent import ScanningAgent
from pentagon.agents.web_app_agent import WebAppAgent
from pentagon.agents.exploitation_agent import ExploitationAgent
from pentagon.core.roe_enforcer import RoEEnforcer, RoEViolation

class Orchestrator:
    """
    Orchestrateur séquentiel des agents PENTAGON.
    
    Pilote l'exécution de la chaîne d'agents et gère l'état partagé.
    """
    
    def __init__(self, llm: LLMClient | None = None, roe_enforcer: RoEEnforcer | None = None):
        """
        Initialise l'orchestrateur et les agents.
        
        Args:
            llm: client LLM partagé entre tous les agents (économie de ressources).
            roe_enforcer: garde-fou RoE. Si None, en crée un avec la politique par défaut.
        """
        # Un seul client LLM partagé par tous les agents
        self.llm = llm or LLMClient()
        
        # Garde-fou RoE (gouvernance)
        self.roe = roe_enforcer or RoEEnforcer()

        # Instanciation des agents
        self.osint_agent = OSINTAgent(llm=self.llm)
        self.scanning_agent = ScanningAgent(llm=self.llm)
        self.web_app_agent = WebAppAgent(llm=self.llm)
        self.exploitation_agent = ExploitationAgent(llm=self.llm)

    def _check_roe(self, target: str, action_category: str, agent_name: str) -> bool:
        """
        Vérifie auprès du RoE si un agent peut s'exécuter.
        
        Args:
            target: cible de l'agent.
            action_category: catégorie d'action de l'agent (passive, active_scan...).
            agent_name: nom de l'agent (pour le log).
        
        Returns:
            True si autorisé, False si refusé (l'agent sera sauté).
        """
        try:
            self.roe.enforce(target, action_category)
            print(f"[RoE] ✓ {agent_name} autorisé ({action_category} sur {target})")
            return True
        except RoEViolation as e:
            print(f"[RoE] ✗ {agent_name} BLOQUÉ : {e}")
            return False


    def run_campaign(
        self,
        target: str,
        scan_profile: str = "web_focused",
    ) -> PentagonState:
        """
        Exécute une campagne complète de reconnaissance et scanning.
        
        Args:
            target: domaine ou URL cible.
            scan_profile: profil de scan Nmap.
        
        Returns:
            L'état PentagonState consolidé en fin de campagne.
        """
        # Initialise l'état partagé
        state = PentagonState(target=target)
        
        print("=" * 70)
        print(f"PENTAGON — Campagne {state.campaign_id[:8]}")
        print(f"Cible : {target}")
        print("=" * 70)
        
        # === PHASE 1 : OSINT (PTES phase 2) ===
        self._run_osint_phase(state, target)
        
        # === PHASE 2 : SCANNING (PTES phase 3) ===
        self._run_scanning_phase(state, target, scan_profile)
         # === PHASE 3 : WEB APP (PTES phase 4) ===
        self._run_web_app_phase(state, target)

        # === PHASE 4 : EXPLOITATION (PTES phase 5) ===
        self._run_exploitation_phase(state, target)

        # === Clôture de la campagne ===
        state.ended_at = datetime.now(timezone.utc).isoformat()
        state.log_event("orchestrator", "campaign_completed",
                        f"{len(state.agents_executed)} agents exécutés")
        
        print("\n" + "=" * 70)
        print(f"✓ Campagne terminée — {len(state.agents_executed)} agents exécutés")
        print("=" * 70)
        
        return state
    
    def _run_osint_phase(self, state: PentagonState, target: str) -> None:
        """Exécute l'agent OSINT et enrichit l'état."""
        print(f"\n{'─' * 70}")
        print(f"PHASE 1 — OSINT & Reconnaissance")
        print(f"{'─' * 70}")
        
        state.log_event("orchestrator", "phase_start", "OSINT")
        
        # Vérification RoE (OSINT = action passive)
        if not self._check_roe(target, "passive", "OSINT_Agent"):
            state.log_error("OSINT_Agent", "Bloqué par le RoE (action passive non autorisée)")
            return

        try:
            osint_result = self.osint_agent.run(target)
            state.osint_result = osint_result
            state.agents_executed.append("OSINT_Agent")
            
            # Extrait le contexte d'infrastructure pour les agents en aval
            self._extract_osint_infrastructure(state, osint_result)
            
            state.log_event("OSINT_Agent", "completed",
                           f"{len(osint_result.get('analysis', {}).get('key_findings', []))} findings")
        
        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            state.log_error("OSINT_Agent", error_msg)
            print(f"❌ Erreur OSINT : {error_msg}")
    
    def _run_scanning_phase(
        self,
        state: PentagonState,
        target: str,
        scan_profile: str,
    ) -> None:
        """Exécute l'agent Scanning avec le contexte OSINT."""
        print(f"\n{'─' * 70}")
        print(f"PHASE 2 — Scanning & Enumeration")
        print(f"{'─' * 70}")
        
        state.log_event("orchestrator", "phase_start", "Scanning")

        # Vérification RoE (Scanning = scan actif)
        if not self._check_roe(target, "active_scan", "Scanning_Agent"):
            state.log_error("Scanning_Agent", "Bloqué par le RoE (scan actif non autorisé)")
            return
        
        # Prépare le contexte OSINT à passer à l'agent Scanning
        osint_context = state.discovered_infrastructure if state.discovered_infrastructure else None
        if osint_context:
            print(f"[Orchestrator] Transmission du contexte OSINT à l'agent Scanning")
            print(f"               Infrastructure connue : {list(osint_context.keys())}")
        
        try:
            scanning_result = self.scanning_agent.run(
                target=target,
                scan_profile=scan_profile,
                osint_context=osint_context,
            )
            state.scanning_result = scanning_result
            state.agents_executed.append("Scanning_Agent")
            
            state.log_event("Scanning_Agent", "completed",
                           f"{len(scanning_result.get('analysis', {}).get('key_findings', []))} findings")
        
        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            state.log_error("Scanning_Agent", error_msg)
            print(f"❌ Erreur Scanning : {error_msg}")

    def _run_web_app_phase(self, state: PentagonState, target: str) -> None:
        """Exécute l'agent Web App avec le contexte des agents précédents."""
        print(f"\n{'─' * 70}")
        print(f"PHASE 3 — Web Application Testing")
        print(f"{'─' * 70}")
        
        state.log_event("orchestrator", "phase_start", "WebApp")
        
        # Vérification RoE (Web App = scan actif)
        if not self._check_roe(target, "active_scan", "WebApp_Agent"):
            state.log_error("WebApp_Agent", "Bloqué par le RoE (scan actif non autorisé)")
            return

        # Prépare les contextes des agents précédents
        osint_context = state.discovered_infrastructure if state.discovered_infrastructure else None
        
        # Extrait un résumé du contexte scanning si disponible
        scanning_context = None
        if state.scanning_result:
            scanning_analysis = state.scanning_result.get("analysis", {})
            scanning_context = {
                "attack_surface": scanning_analysis.get("attack_surface", {}),
                "summary": scanning_analysis.get("summary", ""),
            }
        
        if osint_context or scanning_context:
            print(f"[Orchestrator] Transmission du contexte (OSINT + Scanning) à l'agent Web App")
        
        try:
            web_app_result = self.web_app_agent.run(
                target=target,
                osint_context=osint_context,
                scanning_context=scanning_context,
            )
            state.web_app_result = web_app_result
            state.agents_executed.append("WebApp_Agent")
            
            vulns = web_app_result.get("analysis", {}).get("vulnerabilities", [])
            state.log_event("WebApp_Agent", "completed", f"{len(vulns)} vulnérabilités")
        
        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            state.log_error("WebApp_Agent", error_msg)
            print(f"❌ Erreur Web App : {error_msg}")

    def _run_exploitation_phase(self, state: PentagonState, target: str) -> None:
        """Exécute l'agent Exploitation (offensif) avec le contexte des agents amont."""
        print(f"\n{'─' * 70}")
        print(f"PHASE 4 — Exploitation")
        print(f"{'─' * 70}")

        state.log_event("orchestrator", "phase_start", "Exploitation")

        # Vérification RoE (Exploitation = catégorie offensive).
        # Par défaut, la politique n'autorise PAS 'exploitation' → phase sautée
        # (démonstration du deny-by-default). L'opérateur doit l'autoriser
        # explicitement pour mener les tests offensifs.
        if not self._check_roe(target, "exploitation", "Exploitation_Agent"):
            state.log_error("Exploitation_Agent",
                            "Bloqué par le RoE (exploitation non autorisée)")
            return

        # Contexte transmis : l'agent réutilise les endpoints découverts par le
        # Web App pour cibler ses attaques (login, objets, recherche).
        osint_context = state.discovered_infrastructure if state.discovered_infrastructure else None
        web_app_context = state.web_app_result if state.web_app_result else None
        scanning_context = None
        if state.scanning_result:
            scanning_analysis = state.scanning_result.get("analysis", {})
            scanning_context = {
                "attack_surface": scanning_analysis.get("attack_surface", {}),
                "summary": scanning_analysis.get("summary", ""),
            }

        if web_app_context:
            print(f"[Orchestrator] Transmission du contexte Web App à l'agent Exploitation")

        try:
            exploitation_result = self.exploitation_agent.run(
                target=target,
                web_app_context=web_app_context,
                osint_context=osint_context,
                scanning_context=scanning_context,
            )
            state.exploitation_result = exploitation_result
            state.agents_executed.append("Exploitation_Agent")

            vulns = exploitation_result.get("analysis", {}).get("exploited_vulnerabilities", [])
            state.log_event("Exploitation_Agent", "completed",
                            f"{len(vulns)} vulnérabilités prouvées")

        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            state.log_error("Exploitation_Agent", error_msg)
            print(f"❌ Erreur Exploitation : {error_msg}")

    def _extract_osint_infrastructure(
        self,
        state: PentagonState,
        osint_result: dict[str, Any],
    ) -> None:
        """
        Extrait les informations d'infrastructure des résultats OSINT
        pour les rendre disponibles aux agents en aval.
        """
        analysis = osint_result.get("analysis", {})
        infra_summary = analysis.get("infrastructure_summary", {})
        
        if infra_summary.get("hosting_provider"):
            state.update_infrastructure("hosting_provider", infra_summary["hosting_provider"])
        
        if infra_summary.get("ip_addresses"):
            state.update_infrastructure("ip_addresses", infra_summary["ip_addresses"])
        
        if infra_summary.get("name_servers"):
            state.update_infrastructure("name_servers", infra_summary["name_servers"])
        
        # Ajoute aussi le résumé exécutif OSINT comme contexte
        if osint_result.get("executive_summary"):
            state.update_infrastructure("osint_summary", osint_result["executive_summary"])
    
    def save_campaign(self, state: PentagonState, output_dir: str = "results") -> str:
        """
        Sauvegarde l'état complet de la campagne en JSON.
        
        Returns:
            Le chemin du fichier sauvegardé.
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{output_dir}/campaign_{state.target}_{timestamp}.json"
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(state.to_dict(), f, indent=2, ensure_ascii=False, default=str)
        
        return filename
