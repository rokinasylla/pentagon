"""
Orchestrateur LangGraph de PENTAGON (moteur « graphe »).

Moteur d'orchestration ADDITIONNEL (le moteur séquentiel reste le défaut). Il
réutilise EXACTEMENT les mêmes agents et le même RoE Enforcer, mais les câble
dans une machine à états LangGraph, ce qui apporte :

- **Parallélisme** : Scanning et Web App s'exécutent EN PARALLÈLE après l'OSINT
  (le scan réseau tourne pendant l'analyse applicative).
- **Transition conditionnelle** : l'Exploitation n'est atteinte que si le RoE
  l'autorise (sinon la campagne se termine proprement).
- **Checkpointing** : l'état est persisté à chaque nœud (thread_id) → une
  campagne interrompue peut reprendre.

Le contrat de sortie est IDENTIQUE au moteur séquentiel : run_campaign renvoie
un PentagonState, directement utilisable par save_campaign et le Reporting.

Dépendance : langgraph (importé de façon DIFFÉRÉE dans run_campaign, pour que
le reste de PENTAGON s'importe sans cette librairie).
"""

import operator
from datetime import datetime, timezone
from typing import Annotated, Any, TypedDict

from pentagon.core.state import PentagonState
from pentagon.core.orchestrator import Orchestrator
from pentagon.core.roe_enforcer import RoEViolation


class GraphState(TypedDict, total=False):
    """État circulant dans le graphe (fusion parallèle via reducers sur listes)."""
    target: str
    scan_profile: str
    campaign_id: str
    osint_result: dict[str, Any] | None
    scanning_result: dict[str, Any] | None
    web_app_result: dict[str, Any] | None
    exploitation_result: dict[str, Any] | None
    discovered_infrastructure: dict[str, Any]
    # Reducers : concaténation (sûre même quand Scanning et Web App écrivent en //).
    agents_executed: Annotated[list[str], operator.add]
    errors: Annotated[list[dict[str, Any]], operator.add]
    execution_log: Annotated[list[dict[str, Any]], operator.add]


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(agent: str, event: str, details: str = "") -> dict[str, Any]:
    return {"timestamp": _ts(), "agent": agent, "event": event, "details": details}


def _err(agent: str, error: str) -> dict[str, Any]:
    return {"timestamp": _ts(), "agent": agent, "error": error}


class GraphOrchestrator:
    """
    Orchestrateur basé LangGraph. Compose un Orchestrator séquentiel pour
    réutiliser ses agents, son RoE et ses helpers (aucune duplication de logique
    métier). Seul l'enchaînement change (graphe au lieu d'une suite d'appels).
    """

    def __init__(self, llm=None, roe_enforcer=None):
        self._seq = Orchestrator(llm=llm, roe_enforcer=roe_enforcer)
        self.roe = self._seq.roe
        self.osint_agent = self._seq.osint_agent
        self.scanning_agent = self._seq.scanning_agent
        self.web_app_agent = self._seq.web_app_agent
        self.exploitation_agent = self._seq.exploitation_agent

    # ----------------------------- Nœuds du graphe -----------------------------

    def _node_osint(self, gs: GraphState) -> dict[str, Any]:
        target = gs["target"]
        print(f"\n{'─' * 70}\nPHASE 1 — OSINT & Reconnaissance\n{'─' * 70}")
        if not self._seq._check_roe(target, "passive", "OSINT_Agent"):
            return {"errors": [_err("OSINT_Agent", "Bloqué par le RoE (action passive non autorisée)")]}
        try:
            res = self.osint_agent.run(target)
            # Réutilise l'extraction d'infrastructure du moteur séquentiel.
            tmp = PentagonState(target=target)
            self._seq._extract_osint_infrastructure(tmp, res)
            n = len(res.get("analysis", {}).get("key_findings", []))
            return {
                "osint_result": res,
                "discovered_infrastructure": tmp.discovered_infrastructure,
                "agents_executed": ["OSINT_Agent"],
                "execution_log": [_log("OSINT_Agent", "completed", f"{n} findings")],
            }
        except Exception as e:
            return {"errors": [_err("OSINT_Agent", f"{type(e).__name__}: {e}")]}

    def _node_scanning(self, gs: GraphState) -> dict[str, Any]:
        target = gs["target"]
        print(f"\n{'─' * 70}\nPHASE 2 — Scanning & Enumeration (parallèle)\n{'─' * 70}")
        if not self._seq._check_roe(target, "active_scan", "Scanning_Agent"):
            return {"errors": [_err("Scanning_Agent", "Bloqué par le RoE (scan actif non autorisé)")]}
        osint_context = gs.get("discovered_infrastructure") or None
        try:
            res = self.scanning_agent.run(
                target=target,
                scan_profile=gs.get("scan_profile", "web_focused"),
                osint_context=osint_context,
            )
            n = len(res.get("analysis", {}).get("key_findings", []))
            return {
                "scanning_result": res,
                "agents_executed": ["Scanning_Agent"],
                "execution_log": [_log("Scanning_Agent", "completed", f"{n} findings")],
            }
        except Exception as e:
            return {"errors": [_err("Scanning_Agent", f"{type(e).__name__}: {e}")]}

    def _node_web_app(self, gs: GraphState) -> dict[str, Any]:
        target = gs["target"]
        print(f"\n{'─' * 70}\nPHASE 3 — Web Application Testing (parallèle)\n{'─' * 70}")
        if not self._seq._check_roe(target, "active_scan", "WebApp_Agent"):
            return {"errors": [_err("WebApp_Agent", "Bloqué par le RoE (scan actif non autorisé)")]}
        osint_context = gs.get("discovered_infrastructure") or None
        try:
            # S'exécute en parallèle du Scanning → pas de contexte scanning ici
            # (l'agent Web App fait sa propre découverte JS).
            res = self.web_app_agent.run(
                target=target,
                osint_context=osint_context,
                scanning_context=None,
                scope_check=self._seq.roe.check_target,
            )
            n = len(res.get("analysis", {}).get("vulnerabilities", []))
            return {
                "web_app_result": res,
                "agents_executed": ["WebApp_Agent"],
                "execution_log": [_log("WebApp_Agent", "completed", f"{n} vulnérabilités")],
            }
        except Exception as e:
            return {"errors": [_err("WebApp_Agent", f"{type(e).__name__}: {e}")]}

    def _node_join(self, gs: GraphState) -> dict[str, Any]:
        """Point de synchronisation (fan-in) après Scanning ∥ Web App."""
        return {}

    def _node_exploitation(self, gs: GraphState) -> dict[str, Any]:
        target = gs["target"]
        print(f"\n{'─' * 70}\nPHASE 4 — Exploitation\n{'─' * 70}")
        osint_context = gs.get("discovered_infrastructure") or None
        web_app_context = gs.get("web_app_result") or None
        scanning_context = None
        if gs.get("scanning_result"):
            sa = gs["scanning_result"].get("analysis", {})
            scanning_context = {"attack_surface": sa.get("attack_surface", {}),
                                "summary": sa.get("summary", "")}
        try:
            res = self.exploitation_agent.run(
                target=target,
                web_app_context=web_app_context,
                osint_context=osint_context,
                scanning_context=scanning_context,
                scope_check=self._seq.roe.check_target,
            )
            n = len(res.get("analysis", {}).get("exploited_vulnerabilities", []))
            return {
                "exploitation_result": res,
                "agents_executed": ["Exploitation_Agent"],
                "execution_log": [_log("Exploitation_Agent", "completed", f"{n} vulnérabilités prouvées")],
            }
        except Exception as e:
            return {"errors": [_err("Exploitation_Agent", f"{type(e).__name__}: {e}")]}

    def _node_skip_exploitation(self, gs: GraphState) -> dict[str, Any]:
        """Transition conditionnelle : exploitation NON autorisée par le RoE."""
        print(f"[RoE] ✗ Exploitation sautée (non autorisée par la politique)")
        return {"errors": [_err("Exploitation_Agent", "Bloqué par le RoE (exploitation non autorisée)")]}

    def _route_exploitation(self, gs: GraphState) -> str:
        """Décide, selon le RoE, si l'on exécute l'Exploitation ou si on la saute."""
        try:
            self.roe.enforce(gs["target"], "exploitation")
            return "exploitation"
        except RoEViolation:
            return "skip"

    # ------------------------------- Pilotage ----------------------------------

    def _build_graph(self):
        from langgraph.graph import StateGraph, START, END

        g = StateGraph(GraphState)
        g.add_node("osint", self._node_osint)
        g.add_node("scanning", self._node_scanning)
        g.add_node("web_app", self._node_web_app)
        g.add_node("join", self._node_join)
        g.add_node("exploitation", self._node_exploitation)
        g.add_node("skip_exploitation", self._node_skip_exploitation)

        g.add_edge(START, "osint")
        # Fan-out : Scanning et Web App en PARALLÈLE après l'OSINT.
        g.add_edge("osint", "scanning")
        g.add_edge("osint", "web_app")
        # Fan-in : on attend les deux avant de continuer.
        g.add_edge("scanning", "join")
        g.add_edge("web_app", "join")
        # Transition CONDITIONNELLE : exploitation seulement si le RoE l'autorise.
        g.add_conditional_edges("join", self._route_exploitation,
                                {"exploitation": "exploitation",
                                 "skip": "skip_exploitation"})
        g.add_edge("exploitation", END)
        g.add_edge("skip_exploitation", END)
        return g

    def run_campaign(self, target: str, scan_profile: str = "web_focused",
                     scope_authorizer=None) -> PentagonState:
        """
        Exécute une campagne via le graphe LangGraph.

        scope_authorizer est accepté pour la compatibilité de signature avec le
        moteur séquentiel, mais l'élargissement interactif n'est pas géré par ce
        moteur (périmètre statique).

        Returns:
            Un PentagonState consolidé (contrat identique au moteur séquentiel).
        """
        from langgraph.checkpoint.memory import MemorySaver

        state0 = PentagonState(target=target)
        print("=" * 70)
        print(f"PENTAGON — Campagne {state0.campaign_id[:8]} (moteur LangGraph)")
        print(f"Cible : {target}")
        print("=" * 70)

        checkpointer = MemorySaver()
        app = self._build_graph().compile(checkpointer=checkpointer)

        initial: GraphState = {
            "target": target,
            "scan_profile": scan_profile,
            "campaign_id": state0.campaign_id,
            "discovered_infrastructure": {},
            "agents_executed": [],
            "errors": [],
            "execution_log": [],
        }
        config = {"configurable": {"thread_id": state0.campaign_id}}
        final: GraphState = app.invoke(initial, config=config)

        print("\n" + "=" * 70)
        print(f"✓ Campagne terminée — {len(final.get('agents_executed', []))} agents exécutés")
        print("=" * 70)
        return self._to_pentagon_state(state0, final)

    def _to_pentagon_state(self, base: PentagonState, gs: GraphState) -> PentagonState:
        """Convertit l'état du graphe en PentagonState (pour save + reporting)."""
        base.osint_result = gs.get("osint_result")
        base.scanning_result = gs.get("scanning_result")
        base.web_app_result = gs.get("web_app_result")
        base.exploitation_result = gs.get("exploitation_result")
        base.discovered_infrastructure = gs.get("discovered_infrastructure", {})
        base.agents_executed = gs.get("agents_executed", [])
        base.execution_log = gs.get("execution_log", [])
        base.errors = gs.get("errors", [])
        base.ended_at = _ts()
        return base

    def save_campaign(self, state: PentagonState, output_dir: str = "results") -> str:
        """Délègue la sauvegarde au moteur séquentiel (même format JSON)."""
        return self._seq.save_campaign(state, output_dir=output_dir)
