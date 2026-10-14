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
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask, jsonify, render_template, request, Response, send_file, abort,
    session, redirect, url_for,
)
from werkzeug.security import check_password_hash

# Charge .env (clé DeepSeek, identifiants opérateur, secret de session).
load_dotenv()

app = Flask(__name__)

# ─────────────────────────── Authentification opérateur ────────────────────
# La console est une interface OFFENSIVE : elle ne doit JAMAIS être ouverte
# sans authentification. Un seul compte opérateur, dont le HASH du mot de passe
# est stocké dans .env (jamais en clair). Configurez-le via set_password.py.

app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Passé à True en production derrière TLS (via COOKIE_SECURE=1).
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
)

OPERATOR_USERNAME = os.getenv("OPERATOR_USERNAME", "admin")
OPERATOR_PASSWORD_HASH = os.getenv("OPERATOR_PASSWORD_HASH", "")

# Points d'accès joignables SANS être authentifié.
_PUBLIC_ENDPOINTS = {"login", "static"}


@app.before_request
def _require_login():
    """Garde globale : tout exige une session opérateur, sauf /login et static."""
    if request.endpoint in _PUBLIC_ENDPOINTS:
        return None
    if session.get("operator"):
        return None
    # Non authentifié : JSON pour l'API, redirection pour les pages.
    if request.path.startswith("/api/"):
        return jsonify({"error": "Authentification requise."}), 401
    return redirect(url_for("login"))

# Moteurs d'orchestration proposables dans la console (défaut : séquentiel).
SELECTABLE_ENGINES = {"seq", "langgraph"}

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


# ───────────────────── Liste blanche ADMIN (roe_policy.json) ────────────────
# L'ADMINISTRATEUR maintient les cibles autorisées dans pentagon/config/
# roe_policy.json. L'interface web n'accepte de lancer une campagne QUE sur une
# cible qui y figure ; sinon elle invite l'utilisateur à demander l'autorisation
# de l'admin. Le fichier est relu à CHAQUE requête → l'admin peut l'éditer sans
# redémarrer le serveur.

ADMIN_DENIED_MSG = (
    "⛔ La cible « {t} » n'est pas autorisée par l'administrateur. "
    "Pour la tester, demandez à l'administrateur de l'ajouter à la liste "
    "blanche (fichier roe_policy.json)."
)


def check_admin_authorization(target: str) -> dict:
    """
    Vérifie une cible contre la liste blanche de l'admin (roe_policy.json).

    Réutilise le RoEEnforcer (même normalisation de domaine + deny-by-default)
    en le construisant SANS argument → il charge le fichier admin. Relu à
    chaque appel pour prendre en compte les éditions de l'admin à chaud.

    Returns:
        {"allowed": bool, "categories": [...], "targets": [...]}
        categories = catégories d'action autorisées par l'admin (bornent le
        niveau des tests) ; targets = liste blanche courante.
    """
    try:
        # Import différé (module stdlib pur, pas de stack LLM).
        from pentagon.core.roe_enforcer import RoEEnforcer
        enforcer = RoEEnforcer()  # charge pentagon/config/roe_policy.json
    except Exception:
        # Politique admin absente/illisible → deny-by-default strict.
        return {"allowed": False, "categories": [], "targets": []}

    decision = enforcer.check_target(target)
    return {
        "allowed": bool(decision.get("allowed")),
        "categories": enforcer.policy.get("authorized_action_categories", []) or [],
        "targets": enforcer.policy.get("authorized_targets", []) or [],
    }


def gate_request(target: str, actions: list[str]):
    """
    Applique la gouvernance admin à une requête (plan ou start).

    Returns:
        (effective_actions, error) — si error est non nul, c'est un tuple
        (message, code_http) à renvoyer tel quel ; sinon effective_actions est
        la liste des catégories effectivement permises (bornée par l'admin).
    """
    admin = check_admin_authorization(target)
    if not admin["allowed"]:
        return None, (ADMIN_DENIED_MSG.format(t=target), 403)

    # L'admin borne aussi le niveau : on garde l'intersection des catégories
    # choisies par l'utilisateur et de celles permises par l'admin.
    effective = [a for a in actions if a in admin["categories"]]
    if not effective:
        allowed = ", ".join(admin["categories"]) or "(aucune)"
        return None, (
            "L'administrateur n'autorise aucune des catégories choisies pour "
            f"cette cible. Catégories autorisées par l'admin : {allowed}.", 403)
    return effective, None


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

def _make_orchestrator(engine: str, roe):
    """
    Fabrique l'orchestrateur selon le moteur demandé.

    Les deux moteurs partagent le MÊME contrat (run_campaign/save_campaign) et
    les MÊMES agents + RoE ; seul l'enchaînement change :
      - "seq"       : moteur séquentiel (défaut, sans dépendance).
      - "langgraph" : machine à états LangGraph (Scanning ∥ Web App, routage
                      conditionnel RoE, checkpointing). Import DIFFÉRÉ pour que
                      la console tourne sans langgraph tant qu'on ne le choisit pas.
    """
    if engine == "langgraph":
        from pentagon.core.orchestrator_graph import GraphOrchestrator
        return GraphOrchestrator(roe_enforcer=roe)
    from pentagon.core.orchestrator import Orchestrator
    return Orchestrator(roe_enforcer=roe)


def _run_campaign_job(job_id: str, target: str, actions: list[str],
                      operator: str, scan_profile: str,
                      engine: str = "seq") -> None:
    """Exécute une campagne en tâche de fond, en streamant sa sortie."""
    import contextlib
    import sys

    job = JOBS[job_id]
    # Import différé : la stack LLM n'est chargée qu'ici, au lancement réel.
    from pentagon.core.roe_enforcer import RoEEnforcer

    writer = _JobLogWriter(job, sys.stdout)
    try:
        roe = RoEEnforcer.from_user_input(
            authorized_targets=[target],
            authorized_actions=actions,
            operator_name=operator or "web",
        )
        orchestrator = _make_orchestrator(engine, roe)
        label = "LangGraph (parallèle)" if engine == "langgraph" else "séquentiel"
        job["log"].append(f"[web] Moteur d'orchestration : {label}")

        # langgraph est importé de façon différée (dans run_campaign) → une
        # absence ne se manifeste qu'ici. On la traduit en message clair.
        with contextlib.redirect_stdout(writer):
            state = orchestrator.run_campaign(
                target=target, scan_profile=scan_profile)
            json_path = orchestrator.save_campaign(state)

        job["state"] = state.to_dict()
        job["json_path"] = json_path
        job["summary"] = summarize_state(job["state"])
        job["summary"]["engine"] = engine
        job["status"] = "done"
        job["log"].append(f"[web] Campagne terminée. JSON : {json_path}")
    except ModuleNotFoundError as e:
        job["status"] = "error"
        if "langgraph" in str(e).lower():
            job["error"] = ("Moteur LangGraph indisponible : la librairie "
                            "« langgraph » n'est pas installée sur le serveur "
                            "(pip install langgraph). Utilisez le moteur séquentiel.")
        else:
            job["error"] = f"{type(e).__name__}: {e}"
        job["log"].append(f"[web] ❌ Échec : {job['error']}")
    except Exception as e:
        job["status"] = "error"
        job["error"] = f"{type(e).__name__}: {e}"
        job["log"].append(f"[web] ❌ Échec : {job['error']}")


# ─────────────────────────────────── Routes ────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    """Connexion opérateur (identifiants vérifiés contre le hash du .env)."""
    if not OPERATOR_PASSWORD_HASH:
        return render_template(
            "login.html",
            error="Aucun mot de passe opérateur configuré. "
                  "Exécutez « python set_password.py » sur le serveur."), 503
    error = None
    if request.method == "POST":
        user = (request.form.get("username") or "").strip()
        pwd = request.form.get("password") or ""
        if user == OPERATOR_USERNAME and check_password_hash(OPERATOR_PASSWORD_HASH, pwd):
            session["operator"] = user
            return redirect(url_for("index"))
        error = "Identifiants invalides."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    return render_template(
        "index.html",
        categories=SELECTABLE_CATEGORIES,
        category_labels=CATEGORY_LABELS,
        operator=session.get("operator", ""),
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

    # Gouvernance admin : la cible doit figurer dans roe_policy.json.
    effective, err = gate_request(target, actions)
    if err:
        return jsonify({"error": err[0], "reason": "admin_unauthorized"}), err[1]

    return jsonify({
        "target": target,
        "actions": effective,
        "plan": compute_plan(effective),
        "exploitation": "exploitation" in effective,
    })


@app.route("/api/start", methods=["POST"])
def api_start():
    """Démarre une campagne en tâche de fond, renvoie un job_id."""
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    actions = sanitize_actions(data.get("actions"))
    operator = (data.get("operator") or "").strip()
    scan_profile = (data.get("scan_profile") or "web_focused").strip()
    engine = (data.get("engine") or "seq").strip().lower()
    if engine not in SELECTABLE_ENGINES:
        engine = "seq"

    if not target:
        return jsonify({"error": "URL cible requise."}), 400
    if not actions:
        return jsonify({"error": "Sélectionnez au moins une catégorie RoE."}), 400

    # Gouvernance admin : refuse toute cible hors liste blanche roe_policy.json,
    # et borne les catégories à celles permises par l'admin.
    effective, err = gate_request(target, actions)
    if err:
        return jsonify({"error": err[0], "reason": "admin_unauthorized"}), err[1]
    actions = effective

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
            "engine": engine,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "state": None,
            "json_path": None,
            "pdf_path": None,
            "summary": None,
            "error": None,
        }

    thread = threading.Thread(
        target=_run_campaign_job,
        args=(job_id, target, actions, operator, scan_profile, engine),
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
        quiet = 0
        while True:
            job = JOBS.get(job_id)
            if job is None:
                break
            log = job["log"]
            sent = False
            while idx < len(log):
                yield f"data: {json.dumps({'line': log[idx]})}\n\n"
                idx += 1
                sent = True
            if job["status"] in ("done", "error"):
                payload = {"status": job["status"], "error": job.get("error"),
                           "summary": job.get("summary")}
                yield f"data: {json.dumps(payload)}\n\n"
                break
            # Battement de cœur : pendant les phases silencieuses (longue
            # analyse LLM ~200s), on envoie un commentaire SSE pour maintenir
            # la connexion ouverte et éviter qu'un intermédiaire la coupe.
            quiet = 0 if sent else quiet + 1
            if quiet >= 30:  # ~12 s sans nouvelle ligne
                yield ": keepalive\n\n"
                quiet = 0
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


@app.route("/api/jobs")
def api_jobs():
    """
    Liste des campagnes récentes (en mémoire), pour la RÉCUPÉRATION côté UI.

    Si l'onglet a perdu le fil (rechargement, onglet gelé par le navigateur en
    arrière-plan), la page peut retrouver la dernière campagne terminée et
    réafficher ses résultats + le bouton de génération PDF — sans relancer une
    campagne. Trié du plus récent au plus ancien.
    """
    with _JOBS_LOCK:
        items = [
            {
                "job_id": jid,
                "target": j.get("target", ""),
                "status": j.get("status"),
                "operator": j.get("operator", ""),
                "engine": j.get("engine", "seq"),
                "started_at": j.get("started_at", ""),
                "has_summary": bool(j.get("summary")),
                "has_pdf": bool(j.get("pdf_path")),
            }
            for jid, j in JOBS.items()
        ]
    items.sort(key=lambda x: x["started_at"], reverse=True)
    return jsonify({"jobs": items[:10]})


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
