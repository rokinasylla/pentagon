"""
Magasin de Findings par session pour PENTAGON (Lot UI-2 — jointure web).

Fait le pont entre le résumé de campagne (tel que la console le produit déjà,
summary["findings"]) et l'objet Finding de première classe, et PERSISTE l'état
de preuve à côté des campagnes pour qu'il survive aux redémarrages du service.

Module PUR (stdlib uniquement : pas de Flask, pas de LLM, pas de réseau) : la
dérivation, la persistance (dans un dossier injecté) et la recherche par index
sont testables hors ligne. webapp.py n'est qu'une fine couche HTTP par-dessus.
"""

from __future__ import annotations

import json
import os
from typing import Any

from pentagon.core.finding import (
    Finding, DETECTED, PROVEN, infer_category,
)


def _state_for_source(source: str) -> str:
    """Un finding « prouvé » par la campagne démarre à l'état prouvé, sinon détecté."""
    s = (source or "").strip().lower()
    return PROVEN if s.startswith("prouv") else DETECTED


def finding_from_unified(session_id: str, unified: dict[str, Any],
                         order: int = 0) -> Finding:
    """
    Construit un Finding depuis un finding UNIFIÉ de la console
    (title, severity, source, owasp, cwe, endpoint, description…).

    L'id est STABLE par session+rang pour que l'état de preuve persisté se
    rattache au même finding d'un rechargement à l'autre.
    """
    owasp = str(unified.get("owasp") or "")
    cwe = str(unified.get("cwe") or "")
    title = str(unified.get("title") or "")
    category = infer_category(title, owasp, cwe)
    proof_state = _state_for_source(str(unified.get("source") or ""))

    finding = Finding(
        id=f"{session_id}-{order}",
        session_id=session_id,
        title=title or (category or "Vulnérabilité"),
        category=category,
        severity=str(unified.get("severity") or "info"),
        owasp=owasp,
        cwe=cwe,
        affected_endpoint=str(unified.get("endpoint")
                              or unified.get("affected_endpoint") or ""),
        confidence=float(unified.get("confidence") or 0.0),
        proof_state=proof_state,
    )
    desc = unified.get("description") or unified.get("impact")
    if desc:
        stage = "prove" if proof_state == PROVEN else "detect"
        finding.add_evidence(stage=stage, tool="campaign", snippet=str(desc))
    return finding


def findings_from_summary(session_id: str, summary: dict[str, Any] | None
                          ) -> list[Finding]:
    """Dérive la liste de Finding depuis le résumé de campagne (summary["findings"])."""
    if not summary:
        return []
    unified = summary.get("findings") or []
    return [finding_from_unified(session_id, u, order=i)
            for i, u in enumerate(unified) if isinstance(u, dict)]


# --- Persistance (dossier injecté → testable) -----------------------------
def _store_path(results_dir: str, session_id: str) -> str:
    safe = "".join(c for c in session_id if c.isalnum() or c in "-_")
    return os.path.join(results_dir, f"findings_{safe}.json")


def save_findings(results_dir: str, session_id: str,
                  findings: list[Finding]) -> str:
    """Écrit les Findings d'une session sur disque. Renvoie le chemin."""
    os.makedirs(results_dir, exist_ok=True)
    path = _store_path(results_dir, session_id)
    payload = {"session_id": session_id,
               "findings": [f.to_dict() for f in findings]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def load_findings(results_dir: str, session_id: str) -> list[Finding]:
    """Relit les Findings persistés d'une session (liste vide si absent/illisible)."""
    path = _store_path(results_dir, session_id)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    return [Finding.from_dict(d) for d in (data.get("findings") or [])
            if isinstance(d, dict)]


def get_or_init_findings(results_dir: str, session_id: str,
                         summary: dict[str, Any] | None) -> list[Finding]:
    """
    Renvoie les Findings persistés s'il y en a (état de preuve conservé),
    sinon les dérive du résumé puis les persiste (initialisation).
    """
    existing = load_findings(results_dir, session_id)
    if existing:
        return existing
    derived = findings_from_summary(session_id, summary)
    if derived:
        save_findings(results_dir, session_id, derived)
    return derived


def find_by_index(findings: list[Finding], index: int) -> Finding | None:
    """
    Récupère un Finding par son numéro 1-based (tel que l'opérateur le voit
    dans la console). Hors bornes → None.
    """
    if index is None or index < 1 or index > len(findings):
        return None
    return findings[index - 1]


def find_by_id(findings: list[Finding], finding_id: str) -> Finding | None:
    for f in findings:
        if f.id == finding_id:
            return f
    return None


def replace_finding(findings: list[Finding], updated: Finding) -> list[Finding]:
    """Remplace (par id) un Finding dans la liste ; l'ajoute s'il est absent."""
    out = [updated if f.id == updated.id else f for f in findings]
    if all(f.id != updated.id for f in findings):
        out.append(updated)
    return out
