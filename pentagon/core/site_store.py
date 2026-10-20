"""
Store des sites autorisés PAR OPÉRATEUR (modèle per-operator, Lot UI-6).

Source de vérité : `pentagon/config/sites.json`. Chaque enregistrement décrit un
site autorisé par l'administrateur et attribué à un opérateur, avec son
**périmètre maximal** (catégories RoE), sa **preuve d'autorisation** et son
**statut** :

    {
      "domain": "acme-staging.example.com",
      "operator": "n.sylla",                 # opérateur attribué (ou null)
      "max_categories": ["passive", "active_scan"],
      "proof": "Mandat signé",
      "status": "autorise" | "attente" | "revoque",
      "by": "a.diop",                        # qui a autorisé
      "date": "2026-10-19"
    }

Les **demandes d'accès** d'un opérateur sont des enregistrements de statut
`attente` (créés par l'opérateur, validés par l'admin). Ce modèle colle à la
planche « Admin » (table Domaine / Opérateur / Périmètre max / Statut).

Ce module ne dépend que de la bibliothèque standard : pas de Flask, pas de
réseau — il est testable hors-ligne. `webapp.py` l'utilise et garde
`roe_policy.json` (liste blanche globale lue par le RoEEnforcer) synchronisé
via `authorized_domains()`.
"""

from __future__ import annotations

import json
import os
from datetime import date as _date
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "sites.json"

STATUSES = ("autorise", "attente", "revoque")


def host_of(target: str) -> str:
    """Hôte nu d'une cible (sans schéma ni chemin), en minuscules."""
    t = (target or "").strip()
    if not t:
        return ""
    p = urlparse(t if "//" in t else f"//{t}", scheme="https")
    return (p.netloc or p.path).split("/")[0].lower()


class SiteStore:
    """Lit/écrit `sites.json` et applique la logique per-operator."""

    def __init__(self, path: Optional[str | Path] = None):
        self.path = Path(path) if path else _DEFAULT_PATH
        self.sites: list[dict] = []
        self.reload()

    # --- persistance ------------------------------------------------------

    def reload(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            raw = data.get("sites", []) if isinstance(data, dict) else []
            self.sites = [s for s in raw if isinstance(s, dict) and s.get("domain")]
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            self.sites = []

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"sites": self.sites}, fh, ensure_ascii=False, indent=2)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # --- lecture ----------------------------------------------------------

    def find(self, domain: str) -> Optional[dict]:
        """Enregistrement correspondant à l'hôte de `domain`, ou None."""
        h = host_of(domain)
        return next((s for s in self.sites if host_of(s["domain"]) == h), None)

    def for_operator(self, operator: str) -> list[dict]:
        """Sites autorisés attribués à cet opérateur."""
        return [s for s in self.sites
                if s.get("status") == "autorise" and s.get("operator") == operator]

    def authorized_domains(self) -> list[str]:
        """Domaines de statut `autorise` (pour synchroniser la liste blanche globale)."""
        return [s["domain"] for s in self.sites if s.get("status") == "autorise"]

    def pending(self) -> list[dict]:
        """Demandes d'accès en attente."""
        return [s for s in self.sites if s.get("status") == "attente"]

    def max_categories(self, target: str, operator: str, role: str) -> Optional[list[str]]:
        """
        Périmètre maximal autorisé pour (cible, opérateur, rôle), ou None si la
        cible n'est pas autorisée / pas attribuée à cet opérateur.

        Deny-by-default : un opérateur simple n'a de périmètre que sur SES sites
        attribués et de statut `autorise` ; un admin, sur tout site `autorise`.
        """
        rec = self.find(target)
        if not rec or rec.get("status") != "autorise":
            return None
        if role != "admin" and rec.get("operator") != operator:
            return None
        return list(rec.get("max_categories") or [])

    # --- écriture ---------------------------------------------------------

    def _today(self) -> str:
        return _date.today().isoformat()

    def _upsert(self, rec: dict) -> dict:
        h = host_of(rec["domain"])
        for i, s in enumerate(self.sites):
            if host_of(s["domain"]) == h:
                self.sites[i] = {**s, **rec}
                return self.sites[i]
        self.sites.append(rec)
        return rec

    def authorize(self, domain, operator, max_categories, proof, by, date=None) -> dict:
        """Autorise (ou met à jour) un site attribué à un opérateur."""
        rec = self._upsert({
            "domain": domain.strip(),
            "operator": operator or None,
            "max_categories": list(max_categories or []),
            "proof": proof or "",
            "status": "autorise",
            "by": by,
            "date": date or self._today(),
        })
        self.save()
        return rec

    def request_access(self, domain, operator, date=None) -> dict:
        """Crée une demande d'accès (statut `attente`) pour un opérateur.

        Sans effet si un enregistrement actif (autorise/attente) existe déjà.
        """
        existing = self.find(domain)
        if existing and existing.get("status") in ("autorise", "attente"):
            return existing
        rec = self._upsert({
            "domain": domain.strip(),
            "operator": operator or None,
            "max_categories": [],
            "proof": "",
            "status": "attente",
            "by": f"demande opérateur : {operator}",
            "date": date or self._today(),
        })
        self.save()
        return rec

    def approve(self, domain, max_categories, proof, by, operator=None) -> Optional[dict]:
        """Valide une demande d'accès : `attente` → `autorise`."""
        rec = self.find(domain)
        if not rec:
            return None
        rec["status"] = "autorise"
        rec["max_categories"] = list(max_categories or [])
        rec["proof"] = proof or rec.get("proof", "")
        rec["by"] = by
        rec["date"] = self._today()
        if operator:
            rec["operator"] = operator
        self.save()
        return rec

    def reject(self, domain) -> bool:
        """Refuse/retire une demande d'accès (supprime l'enregistrement `attente`)."""
        rec = self.find(domain)
        if not rec or rec.get("status") != "attente":
            return False
        self.sites = [s for s in self.sites if s is not rec]
        self.save()
        return True

    def revoke(self, domain) -> bool:
        """Révoque un site autorisé (statut `revoque`, conservé pour l'historique)."""
        rec = self.find(domain)
        if not rec:
            return False
        rec["status"] = "revoque"
        rec["operator"] = None
        self.save()
        return True

    def assign_operator(self, domain, operator) -> Optional[dict]:
        """(Ré)attribue un site autorisé à un opérateur."""
        rec = self.find(domain)
        if not rec:
            return None
        rec["operator"] = operator or None
        self.save()
        return rec

    # --- vue publique / amorçage -----------------------------------------

    def to_public(self) -> list[dict]:
        """Projection pour l'UI admin (domaine, opérateur, périmètre, statut…)."""
        out = []
        for s in self.sites:
            cats = s.get("max_categories") or []
            out.append({
                "domain": s["domain"],
                "operator": s.get("operator"),
                "max_categories": list(cats),
                "scope": " · ".join(cats) if cats else ("à définir" if s.get("status") == "attente" else "—"),
                "proof": s.get("proof", ""),
                "status": s.get("status", "autorise"),
                "by": s.get("by", ""),
                "date": s.get("date", ""),
            })
        return out

    def seed_if_empty(self, policy_targets, policy_categories, users) -> bool:
        """
        Amorce le store depuis l'existant s'il est vide (migration douce) :
        chaque cible de la liste blanche globale devient un site `autorise`, avec
        le périmètre global par défaut et l'opérateur déduit de `users.json`
        (premier opérateur dont la liste `sites` contient ce domaine).

        Renvoie True si un amorçage a eu lieu.
        """
        if self.sites:
            return False
        today = self._today()
        owner_by_host: dict[str, str] = {}
        for username, u in (users or {}).items():
            if (u or {}).get("role") == "admin":
                continue
            for s in (u or {}).get("sites") or []:
                owner_by_host.setdefault(host_of(s), username)
        for dom in policy_targets or []:
            self.sites.append({
                "domain": dom,
                "operator": owner_by_host.get(host_of(dom)),
                "max_categories": list(policy_categories or []),
                "proof": "",
                "status": "autorise",
                "by": "amorçage",
                "date": today,
            })
        if self.sites:
            self.save()
            return True
        return False
