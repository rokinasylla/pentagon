#!/usr/bin/env python3
"""
Configure les identifiants de la console web PENTAGON (webapp.py).

Écrit dans le fichier .env :
  - OPERATOR_USERNAME       : nom d'utilisateur opérateur
  - OPERATOR_PASSWORD_HASH  : HASH du mot de passe (jamais le mot de passe en clair)
  - FLASK_SECRET_KEY        : secret de session (généré s'il est absent)

À exécuter SUR LE SERVEUR (la VM) :
    cd ~/pentagon && . .venv/bin/activate && python set_password.py

Le mot de passe est saisi sans écho (getpass) et n'est jamais affiché ni stocké
en clair : seul son hash werkzeug est écrit dans .env (droits 600).
"""

import getpass
import os
import secrets
from pathlib import Path

from werkzeug.security import generate_password_hash

ENV_PATH = Path(__file__).parent / ".env"


def _set_kv(lines: list[str], key: str, value: str) -> list[str]:
    """Remplace (ou ajoute) la ligne KEY=... dans le contenu .env."""
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


def main() -> None:
    user = input("Nom d'utilisateur opérateur [admin] : ").strip() or "admin"
    pwd1 = getpass.getpass("Mot de passe : ")
    pwd2 = getpass.getpass("Confirmer le mot de passe : ")

    if not pwd1:
        print("❌ Mot de passe vide — abandon.")
        return
    if pwd1 != pwd2:
        print("❌ Les mots de passe ne correspondent pas — abandon.")
        return

    pwd_hash = generate_password_hash(pwd1)

    lines = (ENV_PATH.read_text(encoding="utf-8").splitlines(keepends=True)
             if ENV_PATH.exists() else [])
    lines = _set_kv(lines, "OPERATOR_USERNAME", user)
    lines = _set_kv(lines, "OPERATOR_PASSWORD_HASH", pwd_hash)
    if not _has_value(lines, "FLASK_SECRET_KEY"):
        lines = _set_kv(lines, "FLASK_SECRET_KEY", secrets.token_hex(32))

    ENV_PATH.write_text("".join(lines), encoding="utf-8")
    try:
        os.chmod(ENV_PATH, 0o600)
    except OSError:
        pass

    print(f"✅ Identifiants enregistrés dans {ENV_PATH} (opérateur « {user} »).")
    print("   Le mot de passe n'est stocké que sous forme de hash.")
    print("   Redémarrez la console pour prendre en compte les changements.")


if __name__ == "__main__":
    main()
