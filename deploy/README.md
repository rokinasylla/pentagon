# Déploiement durci de PENTAGON (HTTPS + sécurité)

Ce dossier décrit comment exposer la console PENTAGON de façon **sécurisée** sur
la VM Azure : HTTPS de confiance (Let's Encrypt), serveur WSGI de production
(gunicorn) derrière un reverse proxy nginx, et activation des protections
intégrées à l'application.

## Modèle de sécurité (vue d'ensemble)

```
Navigateur ──HTTPS(443)──▶ nginx (TLS, en-têtes) ──HTTP(127.0.0.1:5000)──▶ gunicorn ──▶ Flask (webapp.py)
```

- **nginx** termine le TLS (certificat Let's Encrypt) et relaie en clair vers la
  boucle locale uniquement. gunicorn n'est **jamais** joignable de l'extérieur.
- **Flask** fait confiance aux en-têtes `X-Forwarded-*` de nginx (`ProxyFix`)
  pour connaître le schéma réel (https) et l'IP cliente.

## Protections appliquées côté application (déjà dans `webapp.py`)

| Protection | Détail |
|---|---|
| Cookie de session | `HttpOnly`, `SameSite=Lax`, **`Secure`** (via `COOKIE_SECURE=1`) |
| Clé de session | **obligatoire et stable** en prod (`FLASK_SECRET_KEY`), sinon refus de démarrer |
| En-têtes de sécurité | `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy` |
| Défense CSRF | vérification d'**origine** (Origin/Referer) sur toute requête modifiante, en plus de SameSite |
| Anti-brute-force | verrouillage temporaire après N échecs de connexion par IP |
| Journal d'audit | `logs/audit.log` : connexions, déconnexions, autorisations, lancements de campagne (IP + opérateur) |
| Authentification | mots de passe hachés, auth obligatoire partout (deny-by-default), rôles admin/opérateur |

## Étapes de déploiement

### 1. DNS — pointer un sous-domaine sur la VM
Créez un enregistrement **A** chez votre registrar / zone DNS :

```
pentagon.rokina-sylla.me.   A   <IP_PUBLIQUE_DE_LA_VM>
```

Vérifiez la propagation : `dig +short pentagon.rokina-sylla.me` doit renvoyer l'IP.

### 2. Azure — ouvrir les ports 80 et 443
Dans le groupe de sécurité réseau (NSG) de la VM, autoriser en entrée :
`80/tcp` (HTTP, pour la validation Let's Encrypt + redirection) et `443/tcp` (HTTPS).

### 3. nginx + certbot
```bash
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx
sudo cp deploy/nginx-pentagon.conf /etc/nginx/sites-available/pentagon
sudo ln -s /etc/nginx/sites-available/pentagon /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d pentagon.rokina-sylla.me --redirect
```
certbot installe le certificat, ajoute le bloc `listen 443 ssl` et la
redirection 80 → 443, et programme le renouvellement automatique.

### 4. Secrets (`.env`, hors dépôt git)
```bash
# Clé de session stable (générée UNE fois)
echo "FLASK_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" | sudo tee -a /opt/pentagon/.env
# Cookie de session jamais émis en clair (à activer SEULEMENT une fois le HTTPS en place)
echo "COOKIE_SECURE=1" | sudo tee -a /opt/pentagon/.env
sudo chmod 600 /opt/pentagon/.env
```
> Ordre important : activez `COOKIE_SECURE=1` **après** que le HTTPS fonctionne,
> sinon le cookie de session (Secure) ne sera pas accepté en HTTP.

### 5. Service gunicorn
```bash
/opt/pentagon/.venv/bin/pip install gunicorn
sudo cp deploy/pentagon.service /etc/systemd/system/pentagon.service
sudo systemctl daemon-reload
sudo systemctl enable --now pentagon
systemctl status pentagon
```

### 6. Vérifications
```bash
# HTTPS de confiance + redirection
curl -I http://pentagon.rokina-sylla.me          # -> 301 vers https
curl -I https://pentagon.rokina-sylla.me/console/

# En-têtes de sécurité présents
curl -sI https://pentagon.rokina-sylla.me/console/ | grep -iE \
  'strict-transport|content-security|x-frame|x-content-type|referrer-policy'

# Cookie Secure à la connexion
curl -si https://pentagon.rokina-sylla.me/api/v1/login -X POST \
  -H 'Content-Type: application/json' -H 'Origin: https://pentagon.rokina-sylla.me' \
  -d '{"username":"...","password":"..."}' | grep -i set-cookie   # -> doit contenir "Secure"

# Journal d'audit alimenté
tail -f /opt/pentagon/logs/audit.log
```

## Variables d'environnement de sécurité

| Variable | Défaut | Rôle |
|---|---|---|
| `FLASK_SECRET_KEY` | — | Clé de signature des sessions (**obligatoire** si `COOKIE_SECURE=1`) |
| `COOKIE_SECURE` | `0` | `1` = cookie de session `Secure` (prod HTTPS) |
| `SESSION_IDLE_MINUTES` | `30` | Expiration d'inactivité |
| `LOGIN_FAIL_MAX` | `5` | Échecs tolérés avant verrouillage |
| `LOGIN_FAIL_WINDOW` | `300` | Fenêtre (s) de comptage des échecs |
| `LOGIN_LOCK_SECONDS` | `300` | Durée (s) du verrouillage |
| `PENTAGON_AUDIT_LOG` | `logs/audit.log` | Chemin du journal d'audit |
