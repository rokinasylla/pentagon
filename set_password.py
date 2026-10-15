#!/usr/bin/env python3
"""
Gère les comptes de la console web PENTAGON (webapp.py).

Écrit les comptes dans pentagon/config/users.json :
  { "users": { "<nom>": { "password_hash": "...", "role": "admin|user" } } }

Deux rôles :
  - admin : gère les autorisations de cibles et les comptes ; lance des campagnes.
  - user  : lance des campagnes uniquement sur les cibles autorisées.

Garantit aussi FLASK_SECRET_KEY dans .env (généré s'il est absent).

À exécuter SUR LE SERVEUR (la VM) :
    cd ~/pentagon && . .venv/bin/activate && python set_password.py
    # ajout direct : python set_password.py --username bob --role user

Le mot de passe est saisi sans écho (getpass) et n'est jamais stocké en clair :
seul son hash werkzeug est écrit (fichiers en droits 600).
"""

import argparse
import getpass
import json
import os
import secrets
from pathlib import Path

from werkzeug.security import generate_password_hash

BASE = Path(__file__).parent
ENV_PATH = BASE / ".env"
USERS_PATH = BASE / "pentagon" / "config" / "users.json"
VALID_ROLES = ("admin", "user")


def _set_kv(lines: list[str], key: str, value: str) -> list[str]:
    out, found = [], False
    for ln in lines:
        if ln.strip().startswith(key + "="):
            out.append(f"{key}={value}\n")
            found = True
        else:
            out.append(ln)
    if not found:
        if out and not out[-1].endswith("\n"):
            out[-1] += "\n"
        out.append(f"{key}={value}\n")
    return out


def _has_value(lines: list[str], key: str) -> bool:
    for ln in lines:
        s = ln.strip()
        if s.startswith(key + "=") and s != key + "=":
            return True
    return False


def _ensure_secret_key() -> None:
    lines = (ENV_PATH.read_text(encoding="utf-8").splitlines(keepends=True)
             if ENV_PATH.exists() else [])
    if not _has_value(lines, "FLASK_SECRET_KEY"):
        lines = _set_kv(lines, "FLASK_SECRET_KEY", secrets.token_hex(32))
        ENV_PATH.write_text("".join(lines), encoding="utf-8")
        try:
            os.chmod(ENV_PATH, 0o600)
        except OSError:
            pass


def _load_users() -> dict:
    try:
        return (json.loads(USERS_PATH.read_text(encoding="utf-8")) or {}).get("users", {}) or {}
    except Exception:
        return {}


def _save_users(users: dict) -> None:
    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    USERS_PATH.write_text(json.dumps({"users": users}, ensure_ascii=False, indent=2),
                          encoding="utf-8")
    try:
        os.chmod(USERS_PATH, 0o600)
    except OSError:
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description="Gère les comptes PENTAGON (users.json).")
    ap.add_argument("--username")
    ap.add_argument("--role", choices=VALID_ROLES)
    args = ap.parse_args()

    users = _load_users()
    default_role = "admin" if not any(v.get("role") == "admin" for v in users.values()) else "user"

    user = args.username or input(f"Nom d'utilisateur : ").strip()
    if not user:
        print("❌ Nom vide — abandon.")
        return

    role = args.role
    if not role:
        role = input(f"Rôle (admin/user) [{default_role}] : ").strip().lower() or default_role
    if role not in VALID_ROLES:
        print(f"❌ Rôle invalide ({role}). Choisir : {', '.join(VALID_ROLES)}.")
        return

    pwd1 = getpass.getpass("Mot de passe : ")
    pwd2 = getpass.getpass("Confirmer le mot de passe : ")
    if not pwd1:
        print("❌ Mot de passe vide — abandon.")
        return
    if pwd1 != pwd2:
        print("❌ Les mots de passe ne correspondent pas — abandon.")
        return
    if len(pwd1) < 6:
        print("❌ Mot de passe trop court (min. 6 caractères).")
        return

    existed = user in users
    users[user] = {"password_hash": generate_password_hash(pwd1), "role": role}
    _save_users(users)
    _ensure_secret_key()

    verb = "mis à jour" if existed else "créé"
    print(f"✅ Compte « {user} » {verb} (rôle : {role}) dans {USERS_PATH}.")
    print("   Le mot de passe n'est stocké que sous forme de hash (droits 600).")
    print("   Redémarrez la console pour prendre en compte un nouveau compte.")


if __name__ == "__main__":
    main()
