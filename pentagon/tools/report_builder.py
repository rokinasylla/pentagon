"""
Constructeur de rapport PENTAGON (couche pure, sans dépendance de rendu).

Transforme le JSON consolidé d'une campagne (PentagonState.to_dict()) en un
MODÈLE de rapport normalisé et trié : findings unifiés, comptes de sévérité,
couverture OWASP, éléments de reconnaissance, journal d'audit.

Cette couche est en stdlib PUR (aucune dépendance PDF) : elle est donc
testable hors-ligne. Le rendu PDF (reportlab) consomme ce modèle dans
pentagon/agents/reporting_agent.py.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# Ordre de gravité (du plus grave au moins grave) pour le tri et l'agrégation.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LABELS = ["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    """Vulnérabilité normalisée, quelle que soit sa source (Web App / Exploitation)."""
    source: str                 # "exploitation" (prouvée) ou "web_app" (détectée)
    title: str
    severity: str               # normalisée en minuscules
    proven: bool = False        # True si confirmée par attaque (exploitation)
    owasp: str = ""
    cwe: str = ""
    mitre: str = ""
    endpoint: str = ""
    description: str = ""        # description (web_app) ou impact (exploitation)
    evidence: str = ""          # evidence (web_app) ou proof (exploitation)
    remediation: str = ""
    confidence: float = 0.0

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class ReportModel:
    """Modèle complet d'un rapport, prêt à être rendu."""
    # Métadonnées de campagne
    target: str = ""
    campaign_id: str = ""
    started_at: str = ""
    ended_at: str = ""
    operator: str = ""
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Synthèse
    agents_executed: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    proven_count: int = 0
    detected_count: int = 0
    overall_risk: str = "unknown"
    owasp_coverage: list[str] = field(default_factory=list)

    # Reconnaissance & contexte
    recon_osint_summary: str = ""
    recon_scanning_findings: list[dict[str, Any]] = field(default_factory=list)
    exec_summaries: dict[str, str] = field(default_factory=dict)
    attempted_not_confirmed: list[str] = field(default_factory=list)

    # Gouvernance / audit
    errors: list[dict[str, Any]] = field(default_factory=list)
    execution_log: list[dict[str, Any]] = field(default_factory=list)


def _norm_severity(value: Any) -> str:
    """Normalise une sévérité en minuscules parmi les libellés connus."""
    s = str(value or "info").strip().lower()
    return s if s in SEVERITY_ORDER else "info"


def _exploited_findings(exploitation_result: dict[str, Any]) -> list[Finding]:
    """Extrait les vulnérabilités PROUVÉES par l'agent Exploitation."""
    analysis = (exploitation_result or {}).get("analysis", {})
    findings = []
    for v in analysis.get("exploited_vulnerabilities", []) or []:
        findings.append(Finding(
            source="exploitation",
            proven=True,
            title=v.get("title", "(sans titre)"),
            severity=_norm_severity(v.get("severity")),
            owasp=v.get("owasp_top10", ""),
            cwe=v.get("cwe", ""),
            mitre=v.get("mitre", ""),
            endpoint=v.get("affected_endpoint", ""),
            description=v.get("impact", ""),
            evidence=v.get("proof", ""),
            remediation=v.get("remediation", ""),
            confidence=float(v.get("confidence", 0.0) or 0.0),
        ))
    return findings


def _webapp_findings(web_app_result: dict[str, Any]) -> list[Finding]:
    """Extrait les vulnérabilités DÉTECTÉES par l'agent Web App."""
    analysis = (web_app_result or {}).get("analysis", {})
    findings = []
    for v in analysis.get("vulnerabilities", []) or []:
        findings.append(Finding(
            source="web_app",
            proven=False,
            title=v.get("title", "(sans titre)"),
            severity=_norm_severity(v.get("severity")),
            owasp=v.get("owasp_top10", ""),
            cwe=v.get("cwe", ""),
            endpoint=v.get("affected_endpoint", ""),
            description=v.get("description", ""),
            evidence=v.get("evidence", ""),
            remediation=v.get("remediation", ""),
            confidence=float(v.get("confidence", 0.0) or 0.0),
        ))
    return findings


def _worst_severity(findings: list[Finding]) -> str:
    """Renvoie la pire sévérité présente (pour le risque global)."""
    if not findings:
        return "info"
    return min(findings, key=lambda f: f.severity_rank).severity


def build_report(campaign: dict[str, Any], operator: str = "") -> ReportModel:
    """
    Construit un ReportModel à partir du JSON de campagne.

    Args:
        campaign: dict issu de PentagonState.to_dict().
        operator: nom de l'opérateur (non stocké dans l'état ; fourni ici pour
            la traçabilité du rapport). Optionnel.

    Returns:
        Un ReportModel trié et agrégé, prêt pour le rendu.
    """
    model = ReportModel()
    model.target = campaign.get("target", "")
    model.campaign_id = campaign.get("campaign_id", "")
    model.started_at = campaign.get("started_at", "")
    model.ended_at = campaign.get("ended_at", "") or ""
    model.operator = operator
    model.agents_executed = list(campaign.get("agents_executed", []))
    model.errors = list(campaign.get("errors", []))
    model.execution_log = list(campaign.get("execution_log", []))

    # --- Findings unifiés (prouvés d'abord, puis par gravité) ---
    exploited = _exploited_findings(campaign.get("exploitation_result", {}))
    detected = _webapp_findings(campaign.get("web_app_result", {}))
    findings = exploited + detected
    # Tri : prouvées avant détectées, puis par gravité croissante en rang.
    findings.sort(key=lambda f: (0 if f.proven else 1, f.severity_rank))
    model.findings = findings
    model.proven_count = len(exploited)
    model.detected_count = len(detected)

    # --- Comptes de sévérité (sur l'ensemble des findings) ---
    counts = {label: 0 for label in SEVERITY_LABELS}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    model.severity_counts = counts

    # --- Risque global : priorité au champ des agents, sinon dérivé ---
    exploit_risk = (campaign.get("exploitation_result") or {}).get(
        "analysis", {}).get("overall_risk")
    webapp_risk = (campaign.get("web_app_result") or {}).get(
        "analysis", {}).get("overall_risk")
    declared = [_norm_severity(r) for r in (exploit_risk, webapp_risk) if r]
    if declared:
        model.overall_risk = min(declared, key=lambda s: SEVERITY_ORDER[s])
    else:
        model.overall_risk = _worst_severity(findings)

    # --- Couverture OWASP (catégories uniques, triées) ---
    owasp = {f.owasp.strip() for f in findings if f.owasp.strip()}
    model.owasp_coverage = sorted(owasp)

    # --- Reconnaissance & résumés exécutifs ---
    osint = campaign.get("osint_result") or {}
    model.recon_osint_summary = osint.get("executive_summary", "") or ""

    scanning = campaign.get("scanning_result") or {}
    model.recon_scanning_findings = list(
        scanning.get("analysis", {}).get("key_findings", []) or [])

    for agent_key, label in [
        ("osint_result", "OSINT"),
        ("scanning_result", "Scanning"),
        ("web_app_result", "Web App"),
        ("exploitation_result", "Exploitation"),
    ]:
        res = campaign.get(agent_key) or {}
        summary = res.get("executive_summary", "")
        if summary:
            model.exec_summaries[label] = summary

    # --- Attaques tentées sans succès (preuve d'absence) ---
    model.attempted_not_confirmed = list(
        (campaign.get("exploitation_result") or {}).get(
            "analysis", {}).get("attempted_but_not_confirmed", []) or [])

    return model
