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

import glob
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
from werkzeug.security import check_password_hash, generate_password_hash

# Charge .env (clé DeepSeek, identifiants opérateur, secret de session).
load_dotenv()

app = Flask(__name__)

# ──────────────────── Authentification multi-utilisateur + rôles ────────────
# La console est une interface OFFENSIVE : elle ne doit JAMAIS être ouverte
# sans authentification. Deux RÔLES :
#   - "admin" : gère les AUTORISATIONS (cibles de roe_policy.json, catégories)
#               et les comptes ; peut aussi lancer des campagnes.
#   - "user"  : lance des campagnes UNIQUEMENT sur les cibles autorisées.
# Les comptes {username: {password_hash, role}} vivent dans pentagon/config/
# users.json (jamais de mot de passe en clair). Configurez-les via
# set_password.py. Compat : si users.json est absent mais OPERATOR_* est défini
# dans .env, ce compte est traité comme ADMIN.

app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Passé à True en production derrière TLS (via COOKIE_SECURE=1).
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
)

OPERATOR_USERNAME = os.getenv("OPERATOR_USERNAME", "admin")
OPERATOR_PASSWORD_HASH = os.getenv("OPERATOR_PASSWORD_HASH", "")

USERS_PATH = os.path.join("pentagon", "config", "users.json")
POLICY_PATH = os.path.join("pentagon", "config", "roe_policy.json")
VALID_ROLES = ("admin", "user")

# Points d'accès joignables SANS être authentifié.
_PUBLIC_ENDPOINTS = {"login", "static"}


def load_users() -> dict:
    """Charge {username: {password_hash, role}} depuis users.json (relu à chaud).

    Repli de compatibilité : si users.json est absent/vide mais OPERATOR_* est
    défini dans .env, ce compte unique est présenté comme ADMIN.
    """
    try:
        with open(USERS_PATH, "r", encoding="utf-8") as f:
            users = (json.load(f) or {}).get("users", {}) or {}
        if users:
            return users
    except Exception:
        pass
    if OPERATOR_PASSWORD_HASH:
        return {OPERATOR_USERNAME: {"password_hash": OPERATOR_PASSWORD_HASH,
                                    "role": "admin"}}
    return {}


def save_users(users: dict) -> None:
    """Écrit users.json (indenté) et restreint les permissions si possible."""
    os.makedirs(os.path.dirname(USERS_PATH), exist_ok=True)
    with open(USERS_PATH, "w", encoding="utf-8") as f:
        json.dump({"users": users}, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(USERS_PATH, 0o600)
    except OSError:
        pass


def authenticate(username: str, password: str):
    """Retourne le rôle si les identifiants sont valides, sinon None."""
    u = load_users().get(username)
    if u and u.get("password_hash") and check_password_hash(u["password_hash"], password):
        return u.get("role", "user")
    return None


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


def require_admin():
    """Garde de rôle pour les routes d'administration (à appeler en tête).

    Retourne une réponse d'erreur si l'utilisateur n'est pas admin, sinon None.
    """
    if session.get("role") == "admin":
        return None
    if request.path.startswith("/api/"):
        return jsonify({"error": "Action réservée à l'administrateur."}), 403
    return redirect(url_for("index"))


def load_policy() -> dict:
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_policy(policy: dict) -> None:
    with open(POLICY_PATH, "w", encoding="utf-8") as f:
        json.dump(policy, f, ensure_ascii=False, indent=2)

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

# ─────────────────── Persistance : disque → registre (Lot 5) ────────────────
# Les campagnes vivaient UNIQUEMENT en mémoire → perdues au moindre redémarrage
# du service (rapport soudain « introuvable »). Or chaque campagne terminée est
# déjà sauvegardée en JSON complet dans results/. On fait donc du DISQUE la
# source de vérité : au démarrage (et à chaque /api/jobs) on recharge les
# campagnes terminées dans JOBS → elles SURVIVENT aux redémarrages, et les
# campagnes lancées en CLI apparaissent aussi dans la console.

RESULTS_DIR = os.getenv("PENTAGON_RESULTS_DIR", "results")
# Chemins déjà traités (fichier chargé OU illisible) → scan bon marché ensuite.
_PERSISTED_PATHS: set[str] = set()


def _persisted_job_id(state: dict, path: str) -> str:
    """ID stable d'une campagne persistée (dérivé du campaign_id, sinon du nom)."""
    cid = (state.get("campaign_id") or "").replace("-", "")
    return cid[:12] if cid else os.path.splitext(os.path.basename(path))[0][:12]


def lookup_job(job_id: str):
    """Retrouve un job ; sur échec, resynchronise le disque puis réessaie.

    Rend les liens directs (/api/result|report|download) robustes après un
    redémarrage du service, même si l'UI n'a pas encore appelé /api/jobs.
    """
    job = JOBS.get(job_id)
    if job is None:
        sync_persisted_jobs()
        job = JOBS.get(job_id)
    return job


def sync_persisted_jobs() -> None:
    """
    Charge dans JOBS les campagnes terminées de results/*.json absentes du
    registre. Idempotent : ignore les fichiers déjà vus. Sans stack LLM (seul
    summarize_state, pur, est utilisé) → n'alourdit pas l'import du module.
    """
    try:
        # Uniquement les campagnes COMPLÈTES (save_campaign -> campaign_*.json),
        # jamais les sorties d'agents isolées (osint_*.json, scanning_*.json…).
        paths = glob.glob(os.path.join(RESULTS_DIR, "campaign_*.json"))
    except Exception:
        return
    for path in paths:
        if path in _PERSISTED_PATHS:
            continue
        _PERSISTED_PATHS.add(path)  # marqué quoi qu'il arrive (évite de retenter)
        try:
            with open(path, "r", encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            continue
        job_id = _persisted_job_id(state, path)
        with _JOBS_LOCK:
            if job_id in JOBS:
                continue
            try:
                summary = summarize_state(state)
                summary["engine"] = "seq"
            except Exception:
                summary = None
            JOBS[job_id] = {
                "status": "done",
                "log": [],
                "target": state.get("target", ""),
                "actions": [],
                "operator": "",
                "engine": "seq",
                "started_at": state.get("started_at") or state.get("ended_at") or "",
                "state": state,
                "json_path": path,
                "pdf_path": None,
                "summary": summary,
                "error": None,
                "persisted": True,
            }


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
    """Connexion (identifiants vérifiés contre users.json, repli .env)."""
    if not load_users():
        return render_template(
            "login.html",
            error="Aucun compte configuré. "
                  "Exécutez « python set_password.py » sur le serveur."), 503
    error = None
    if request.method == "POST":
        user = (request.form.get("username") or "").strip()
        pwd = request.form.get("password") or ""
        role = authenticate(user, pwd)
        if role:
            session["operator"] = user
            session["role"] = role
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
        role=session.get("role", "user"),
    )


# ─────────────────────────── Administration (rôle admin) ────────────────────

@app.route("/api/admin/policy")
def api_admin_policy():
    """Lit la politique RoE (cibles autorisées + catégories). Admin only."""
    guard = require_admin()
    if guard is not None:
        return guard
    try:
        p = load_policy()
    except Exception as e:
        return jsonify({"error": f"Politique illisible : {e}"}), 500
    return jsonify({
        "targets": p.get("authorized_targets", []) or [],
        "categories": p.get("authorized_action_categories", []) or [],
        "all_categories": SELECTABLE_CATEGORIES,
    })


@app.route("/api/admin/targets", methods=["POST", "DELETE"])
def api_admin_targets():
    """Ajoute (POST) ou retire (DELETE) une cible autorisée. Admin only."""
    guard = require_admin()
    if guard is not None:
        return guard
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Cible requise."}), 400
    try:
        p = load_policy()
        tg = p.setdefault("authorized_targets", [])
        if request.method == "POST":
            if target not in tg:
                tg.append(target)
        else:
            p["authorized_targets"] = [t for t in tg if t != target]
        save_policy(p)
    except Exception as e:
        return jsonify({"error": f"Écriture impossible : {e}"}), 500
    return jsonify({"targets": p.get("authorized_targets", [])})


@app.route("/api/admin/categories", methods=["POST"])
def api_admin_categories():
    """Définit les catégories d'action autorisées par l'admin. Admin only."""
    guard = require_admin()
    if guard is not None:
        return guard
    data = request.get_json(force=True, silent=True) or {}
    given = {str(c).strip().lower() for c in (data.get("categories") or [])}
    cats = [c for c in SELECTABLE_CATEGORIES if c in given]
    try:
        p = load_policy()
        p["authorized_action_categories"] = cats
        save_policy(p)
    except Exception as e:
        return jsonify({"error": f"Écriture impossible : {e}"}), 500
    return jsonify({"categories": cats})


def _admin_count(users: dict) -> int:
    return sum(1 for v in users.values() if v.get("role") == "admin")


@app.route("/api/admin/users", methods=["GET", "POST", "PATCH", "DELETE"])
def api_admin_users():
    """Gestion complète des comptes (users ET admins). Admin only.

    Un admin connecté peut créer/réinitialiser (POST), changer le rôle (PATCH)
    et supprimer (DELETE) n'importe quel compte. Le TOUT PREMIER admin est
    amorcé en ligne de commande (set_password.py / repli .env) ; ensuite tout
    se gère ici. Le mot de passe (via TLS) est HACHÉ côté serveur, jamais en
    clair. Garde-fous anti-verrouillage : impossible de supprimer/rétrograder
    le DERNIER admin, ni de supprimer/rétrograder SON PROPRE compte.
    """
    guard = require_admin()
    if guard is not None:
        return guard
    users = load_users()
    me = session.get("operator")

    if request.method == "GET":
        return jsonify({"users": [
            {"username": u, "role": users[u].get("role", "user")}
            for u in sorted(users)
        ]})

    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"error": "Nom d'utilisateur requis."}), 400

    if request.method == "DELETE":
        if username not in users:
            return jsonify({"error": "Compte introuvable."}), 404
        if username == me:
            return jsonify({"error": "Impossible de supprimer son propre compte."}), 400
        if users[username].get("role") == "admin" and _admin_count(users) <= 1:
            return jsonify({"error": "Impossible de supprimer le dernier admin."}), 400
        del users[username]
        save_users(users)
        return jsonify({"ok": True})

    role = (data.get("role") or "user").strip().lower()
    if role not in VALID_ROLES:
        role = "user"

    if request.method == "PATCH":  # changement de rôle (sans toucher au mot de passe)
        if username not in users:
            return jsonify({"error": "Compte introuvable."}), 404
        if username == me and role != "admin":
            return jsonify({"error": "Impossible de retirer son propre rôle admin."}), 400
        if users[username].get("role") == "admin" and role != "admin" and _admin_count(users) <= 1:
            return jsonify({"error": "Impossible de rétrograder le dernier admin."}), 400
        users[username]["role"] = role
        save_users(users)
        return jsonify({"ok": True, "username": username, "role": role})

    # POST : création / réinitialisation (mot de passe + rôle)
    password = data.get("password") or ""
    if len(password) < 6:
        return jsonify({"error": "Mot de passe trop court (min. 6 caractères)."}), 400
    if (username in users and users[username].get("role") == "admin"
            and role != "admin" and _admin_count(users) <= 1):
        return jsonify({"error": "Impossible de rétrograder le dernier admin."}), 400
    users[username] = {"password_hash": generate_password_hash(password), "role": role}
    save_users(users)
    return jsonify({"ok": True, "username": username, "role": role})


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
    job = lookup_job(job_id)
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
    sync_persisted_jobs()  # intègre les campagnes terminées trouvées sur disque
    with _JOBS_LOCK:
        items = []
        for jid, j in JOBS.items():
            s = j.get("summary") or {}
            items.append({
                "job_id": jid,
                "target": j.get("target", ""),
                "status": j.get("status"),
                "operator": j.get("operator", ""),
                "engine": j.get("engine", "seq"),
                "started_at": j.get("started_at", ""),
                "has_summary": bool(j.get("summary")),
                "has_pdf": bool(j.get("pdf_path")),
                # Résumé compact pour l'historique (sans réouvrir la campagne).
                "proven_count": s.get("proven_count", 0),
                "detected_count": s.get("detected_count", 0),
                "overall_risk": s.get("overall_risk", "unknown"),
            })
    items.sort(key=lambda x: x["started_at"], reverse=True)
    return jsonify({"jobs": items[:10]})


@app.route("/api/report/<job_id>", methods=["POST"])
def api_report(job_id: str):
    """Génère le rapport PDF de la campagne (import reportlab différé)."""
    job = lookup_job(job_id)
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


GROUND_TRUTH_PATH = os.path.join("benchmark", "vulnshop_ground_truth.json")


@app.route("/api/evaluate/<job_id>")
def api_evaluate(job_id: str):
    """
    Évalue une campagne terminée contre la vérité terrain (Lot 6) et renvoie
    les métriques précision/rappel/F1 + le rapport Markdown (pour téléchargement
    côté client). 100% pur (aucun LLM, aucun réseau).
    """
    job = lookup_job(job_id)
    if job is None:
        abort(404)
    if job["status"] != "done" or not job.get("state"):
        return jsonify({"error": "Campagne non terminée."}), 400
    try:
        from pentagon.tools.evaluation_tool import score_campaign
        from evaluate import render_markdown
        with open(GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
            ground_truth = json.load(f)
    except Exception as e:
        return jsonify({
            "error": f"Banc de vérité terrain indisponible : {e}"}), 500

    res = score_campaign(job["state"], ground_truth)
    # Avertissement si la cible ne correspond pas au banc (métriques non
    # pertinentes hors VulnShop).
    hint = (ground_truth.get("target_hint") or "").lower()
    tgt = str(res.get("target", "")).lower()
    res["off_benchmark"] = bool(hint and hint not in tgt)
    res["benchmark_hint"] = ground_truth.get("target_hint", "")
    res["markdown"] = render_markdown(res)
    return jsonify(res)


@app.route("/api/download/<job_id>/<kind>")
def api_download(job_id: str, kind: str):
    job = lookup_job(job_id)
    if job is None:
        abort(404)
    path = job.get("json_path") if kind == "json" else job.get("pdf_path")
    if not path or not os.path.exists(path):
        abort(404)
    return send_file(os.path.abspath(path), as_attachment=True)


# Au chargement du module (service systemd ou gunicorn), on recharge les
# campagnes terminées déjà sur disque → la reprise fonctionne dès la 1re page.
sync_persisted_jobs()


if __name__ == "__main__":
    print("PENTAGON — interface web sur http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, threaded=True, debug=False)
