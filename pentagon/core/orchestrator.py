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


class Orchestrator:
    """
    Orchestrateur séquentiel des agents PENTAGON.
    
    Pilote l'exécution de la chaîne d'agents et gère l'état partagé.
    """
    
    def __init__(self, llm: LLMClient | None = None):
        """
        Initialise l'orchestrateur et les agents.
        
        Args:
            llm: client LLM partagé entre tous les agents (économie de ressources).
        """
        # Un seul client LLM partagé par tous les agents
        self.llm = llm or LLMClient()
        
        # Instanciation des agents
        self.osint_agent = OSINTAgent(llm=self.llm)
        self.scanning_agent = ScanningAgent(llm=self.llm)
    
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
