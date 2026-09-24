#!/usr/bin/env python3
"""
PENTAGON — Interface web opérateur (Flask).

Nouvelle façade graphique au-dessus du MÊME cœur que la CLI : l'utilisateur
saisit l'URL d'une cible, choisit ses catégories RoE, valide le plan
(deny-by-default), puis suit la campagne EN DIRECT (progression phase par
phase streamée depuis l'orchestrateur), avant de consulter les résultats et
de télécharger le rapport PDF.

Principe inchangé : aucune cible n'est codée en dur — tout vient de l'opérateur
via l'interface, exactement comme pentagon.py. Le RoE Enforcer garde la
gouvernance (deny-by-default), l'interface ne fait que la SURFACER.

Exécution (sur Kali) :
    pip install flask reportlab
    python webapp.py
    # puis ouvrir http://127.0.0.1:5000

Note : l'import de l'Orchestrator (stack LLM) est DIFFÉRÉ dans le worker, donc
ce module s'importe sans la stack — seule une campagne réelle la charge.
"""

import io
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone

from flask import (
    Flask, jsonify, render_template, request, Response, send_file, abort,
)

app = Flask(__name__)

# Catégories RoE proposables (destructive jamais offerte — charte éthique).
SELECTABLE_CATEGORIES = ["passive", "active_scan", "exploitation"]
CATEGORY_LABELS = {
    "passive": "Reconnaissance passive (WHOIS, DNS, bundle JS)",
    "active_scan": "Scan actif (Nmap, endpoints, headers)",
    "exploitation": "Tests offensifs (SQLi, XSS, bypass d'auth)",
}
# Quelle phase dépend de quelle catégorie (pour l'aperçu deny-by-default).
PHASE_CATEGORY = [
    ("OSINT", "passive"),
    ("Scanning", "active_scan"),
    ("Web App", "active_scan"),
    ("Exploitation", "exploitation"),
]

# Registre des campagnes en mémoire (outil local mono-utilisateur).
JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()


# ─────────────────────────── Logique pure (testable) ───────────────────────

def sanitize_actions(raw_actions) -> list[str]:
    """Garde uniquement les catégories valides, dans l'ordre canonique."""
    given = {str(a).strip().lower() for a in (raw_actions or [])}
    return [c for c in SELECTABLE_CATEGORIES if c in given]


def compute_plan(actions: list[str]) -> list[dict]:
    """Renvoie l'état de chaque phase (exécutée/sautée) selon le RoE choisi."""
    return [
        {"phase": phase, "category": cat, "enabled": cat in actions}
        for phase, cat in PHASE_CATEGORY
    ]


def summarize_state(state_dict: dict) -> dict:
    """Extrait un résumé compact des résultats pour l'affichage."""
    from collections import Counter

    web = (state_dict.get("web_app_result") or {}).get("analysis", {})
    exp = (state_dict.get("exploitation_result") or {}).get("analysis", {})

    detected = web.get("vulnerabilities", []) or []
    proven = exp.get("exploited_vulnerabilities", []) or []

    def counts(items):
        return dict(Counter(v.get("severity", "info") for v in items))

    return {
        "target": state_dict.get("target", ""),
        "campaign_id": state_dict.get("campaign_id", ""),
        "agents_executed": state_dict.get("agents_executed", []),
        "n_errors": len(state_dict.get("errors", [])),
        "detected_count": len(detected),
        "proven_count": len(proven),
        "detected_by_severity": counts(detected),
        "proven_by_severity": counts(proven),
        "overall_risk": exp.get("overall_risk") or web.get("overall_risk") or "unknown",
        "findings": _unify_findings(proven, detected),
    }


# Ordre de sévérité pour le tri d'affichage.
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _unify_findings(proven: list[dict], detected: list[dict]) -> list[dict]:
    """
    Fusionne les vulnérabilités PROUVÉES (agent Exploitation) et DÉTECTÉES
    (agent Web App) en une liste unifiée pour l'affichage : nom, sévérité,
    description et IMPACT sécurité tels qu'interprétés par le LLM.

    Prouvées d'abord, puis par sévérité décroissante.
    """
    out: list[dict] = []

    for v in proven:
        out.append({
            "title": v.get("title", "Vulnérabilité"),
            "severity": v.get("severity", "info"),
            "source": "prouvée",
            "owasp": v.get("owasp_top10") or v.get("owasp", ""),
            "cwe": v.get("cwe", ""),
            "endpoint": v.get("affected_endpoint", ""),
            # Pour une faille prouvée, la "preuve" décrit ce qui a été démontré.
            "description": v.get("proof") or v.get("description", ""),
            "impact": v.get("impact", ""),
            "remediation": v.get("remediation", ""),
            "confidence": v.get("confidence"),
        })

    for v in detected:
        out.append({
            "title": v.get("title", "Vulnérabilité"),
            "severity": v.get("severity", "info"),
            "source": "détectée",
            "owasp": v.get("owasp_top10") or v.get("owasp", ""),
            "cwe": v.get("cwe", ""),
            "endpoint": v.get("affected_endpoint", ""),
            "description": v.get("description", ""),
            # L'agent Web App expose une "evidence" ; à défaut d'un champ impact.
            "impact": v.get("impact") or v.get("evidence", ""),
            "remediation": v.get("remediation", ""),
            "confidence": v.get("confidence"),
        })

    out.sort(key=lambda f: (0 if f["source"] == "prouvée" else 1,
                            _SEV_ORDER.get(f["severity"], 9)))
    return out


# ─────────────────────────── Capture de la sortie ──────────────────────────

class _JobLogWriter(io.TextIOBase):
    """
    Fichier-like qui capture le stdout de l'orchestrateur ligne par ligne
    dans le buffer du job (pour le streaming SSE), tout en le renvoyant aussi
    vers la console réelle.
    """

    def __init__(self, job: dict, mirror):
        self._job = job
        self._mirror = mirror
        self._buffer = ""

    def write(self, s: str) -> int:
        self._mirror.write(s)
        self._buffer += s
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            self._job["log"].append(line)
        return len(s)

    def flush(self):
        self._mirror.flush()


# ─────────────────────────────── Worker campagne ───────────────────────────

def _run_campaign_job(job_id: str, target: str, actions: list[str],
                      operator: str, scan_profile: str) -> None:
    """Exécute une campagne en tâche de fond, en streamant sa sortie."""
    import contextlib
    import sys

    job = JOBS[job_id]
    # Imports différés : la stack LLM n'est chargée qu'ici, au lancement réel.
    from pentagon.core.orchestrator import Orchestrator
    from pentagon.core.roe_enforcer import RoEEnforcer

    writer = _JobLogWriter(job, sys.stdout)
    try:
        roe = RoEEnforcer.from_user_input(
            authorized_targets=[target],
            authorized_actions=actions,
            operator_name=operator or "web",
        )
        orchestrator = Orchestrator(roe_enforcer=roe)

        with contextlib.redirect_stdout(writer):
            state = orchestrator.run_campaign(
                target=target, scan_profile=scan_profile)
            json_path = orchestrator.save_campaign(state)

        job["state"] = state.to_dict()
        job["json_path"] = json_path
        job["summary"] = summarize_state(job["state"])
        job["status"] = "done"
        job["log"].append(f"[web] Campagne terminée. JSON : {json_path}")
    except Exception as e:
        job["status"] = "error"
        job["error"] = f"{type(e).__name__}: {e}"
        job["log"].append(f"[web] ❌ Échec : {job['error']}")


# ─────────────────────────────────── Routes ────────────────────────────────

@app.route("/")
def index():
    return render_template(
        "index.html",
        categories=SELECTABLE_CATEGORIES,
        category_labels=CATEGORY_LABELS,
    )


@app.route("/api/plan", methods=["POST"])
def api_plan():
    """Aperçu du plan (phases exécutées/sautées) — deny-by-default."""
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    actions = sanitize_actions(data.get("actions"))
    if not target:
        return jsonify({"error": "URL cible requise."}), 400
    if not actions:
        return jsonify({"error": "Sélectionnez au moins une catégorie RoE."}), 400
    return jsonify({
        "target": target,
        "actions": actions,
        "plan": compute_plan(actions),
        "exploitation": "exploitation" in actions,
    })


@app.route("/api/start", methods=["POST"])
def api_start():
    """Démarre une campagne en tâche de fond, renvoie un job_id."""
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    actions = sanitize_actions(data.get("actions"))
    operator = (data.get("operator") or "").strip()
    scan_profile = (data.get("scan_profile") or "web_focused").strip()

    if not target:
        return jsonify({"error": "URL cible requise."}), 400
    if not actions:
        return jsonify({"error": "Sélectionnez au moins une catégorie RoE."}), 400

    # Un seul job actif à la fois (capture stdout globale + outil local).
    with _JOBS_LOCK:
        if any(j["status"] == "running" for j in JOBS.values()):
            return jsonify({"error": "Une campagne est déjà en cours."}), 409
        job_id = uuid.uuid4().hex[:12]
        JOBS[job_id] = {
            "status": "running",
            "log": [],
            "target": target,
            "actions": actions,
            "operator": operator,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "state": None,
            "json_path": None,
            "pdf_path": None,
            "summary": None,
            "error": None,
        }

    thread = threading.Thread(
        target=_run_campaign_job,
        args=(job_id, target, actions, operator, scan_profile),
        daemon=True,
    )
    thread.start()
    return jsonify({"job_id": job_id})


@app.route("/api/stream/<job_id>")
def api_stream(job_id: str):
    """Flux SSE : lignes de log en direct puis statut final."""
    if job_id not in JOBS:
        abort(404)

    def generate():
        idx = 0
        while True:
            job = JOBS.get(job_id)
            if job is None:
                break
            log = job["log"]
            while idx < len(log):
                yield f"data: {json.dumps({'line': log[idx]})}\n\n"
                idx += 1
            if job["status"] in ("done", "error"):
                payload = {"status": job["status"], "error": job.get("error"),
                           "summary": job.get("summary")}
                yield f"data: {json.dumps(payload)}\n\n"
                break
            time.sleep(0.4)

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/result/<job_id>")
def api_result(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        abort(404)
    return jsonify({
        "status": job["status"],
        "summary": job.get("summary"),
        "error": job.get("error"),
        "has_json": bool(job.get("json_path")),
        "has_pdf": bool(job.get("pdf_path")),
    })


@app.route("/api/report/<job_id>", methods=["POST"])
def api_report(job_id: str):
    """Génère le rapport PDF de la campagne (import reportlab différé)."""
    job = JOBS.get(job_id)
    if job is None:
        abort(404)
    if job["status"] != "done" or not job.get("state"):
        return jsonify({"error": "Campagne non terminée."}), 400
    try:
        from pentagon.agents.reporting_agent import ReportingAgent
        pdf_path = ReportingAgent().run(
            campaign=job["state"], operator=job.get("operator", ""))
        job["pdf_path"] = pdf_path
        return jsonify({"pdf": os.path.basename(pdf_path)})
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/download/<job_id>/<kind>")
def api_download(job_id: str, kind: str):
    job = JOBS.get(job_id)
    if job is None:
        abort(404)
    path = job.get("json_path") if kind == "json" else job.get("pdf_path")
    if not path or not os.path.exists(path):
        abort(404)
    return send_file(os.path.abspath(path), as_attachment=True)


if __name__ == "__main__":
    print("PENTAGON — interface web sur http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, threaded=True, debug=False)
