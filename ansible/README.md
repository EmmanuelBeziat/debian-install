# Debian Server Ansible Playbooks

Automatisation complète de l'installation d'un serveur Debian avec Ansible, basée sur le guide [debian-install](../README.md).

## Prérequis

- Ansible 2.9+
- Accès SSH root au serveur Debian
- Une clé SSH publique renseignée dans `ssh_authorized_keys` (`group_vars/all/vars.yml`) : `02-ssh-setup.yml` la dépose avant de couper la connexion par mot de passe, et refuse de tourner sans elle
- Sur un serveur neuf qui n'accepte que le mot de passe : `ssh-copy-id root@IP` avant le premier lancement. Le port (22 sur un serveur neuf, `ssh_port` ensuite) est détecté automatiquement

## Installation

### 1. Configuration

Copiez les fichiers d'exemple et modifiez-les avec vos propres valeurs :

```bash
cd ansible
mkdir -p group_vars/all
cp group_vars/all.yml.example group_vars/all/vars.yml
cp group_vars/vault.yml.example group_vars/all/vault.yml
```

### 2. Configuration des variables

Éditez `group_vars/all/vars.yml` avec vos paramètres :

```yaml
server_ip: "VOTRE_IP_SERVEUR"
server_hostname: "votre_hostname"
ssh_port: 2222
mail_domain: "votre-domaine.com"
admin_email: "admin@votre-domaine.com"
crowdsec_whitelist_ip: "VOTRE_IP_ADMIN"
```

Éditez `group_vars/all/vault.yml` avec vos mots de passe :

```yaml
mariadb_root_password: "MOT_DE_PASSE_ROOT"
mail_db_password: "MOT_DE_PASSE_MAIL"
mariadb_admin_password: "MOT_DE_PASSE_ADMIN"
ftp_host: "ftp.example.com"
ftp_user: "backup_user"
ftp_password: "MOT_DE_PASSE_FTP"
```

### 3. Configuration de l'inventaire

`inventory/hosts.ini` lit `server_ip` et `ssh_port` dans `group_vars/all/vars.yml`, il n'y a rien à modifier :

```ini
[servers]
debian-server ansible_host="{{ server_ip }}" ansible_port="{{ ssh_port }}" ansible_user=root

[servers:vars]
ansible_python_interpreter=/usr/bin/python3
```

Pour lancer Ansible directement sur le serveur à installer (pas de poste de contrôle, par exemple en reprise après sinistre quand l'ancien serveur n'existe plus) : installer `ansible-core` et `git` sur le serveur, cloner ce dépôt, et utiliser `inventory/local.ini` à la place de `inventory/hosts.ini` dans toutes les commandes.

## Utilisation

### Installation complète

```bash
ansible-playbook -i inventory/hosts.ini site.yml
```

### Installation minimale (système + SSH + Apache)

```bash
ansible-playbook -i inventory/hosts.ini minimal.yml
```

### Playbooks individuels

```bash
# Système de base
ansible-playbook -i inventory/hosts.ini playbooks/01-system-setup.yml

# SSH
ansible-playbook -i inventory/hosts.ini playbooks/02-ssh-setup.yml

# Apache
ansible-playbook -i inventory/hosts.ini playbooks/03-apache-setup.yml

# Nginx
ansible-playbook -i inventory/hosts.ini playbooks/04-nginx-setup.yml

# PHP
ansible-playbook -i inventory/hosts.ini playbooks/05-php-setup.yml

# NodeJS
ansible-playbook -i inventory/hosts.ini playbooks/06-nodejs-setup.yml

# MariaDB
ansible-playbook -i inventory/hosts.ini playbooks/07-mariadb-setup.yml

# Serveur mail complet
ansible-playbook -i inventory/hosts.ini playbooks/11-mail-server.yml

# Sécurité
ansible-playbook -i inventory/hosts.ini playbooks/14-ufw-setup.yml
ansible-playbook -i inventory/hosts.ini playbooks/16-crowdsec-setup.yml
```

## Restauration depuis les sauvegardes

`restore.yml` remet un serveur dans l'état de la dernière sauvegarde, **après** un `site.yml` complet. Il dépose la config (`/etc`, `/opt`, crontab, clés SSH et DKIM…), les bases (comptes et droits compris), les boîtes mail et les fichiers des sites, puis reclone les dépôts git déployés, relance les scripts de déploiement du webhook et les applications PM2.

1. Récupérez les archives (`*_conf-files.zip`, `*_mysql.zip`, `*_mails.zip`, `*_sites.zip`) depuis le FTP ou Google Drive dans un dossier de la machine qui lance Ansible. La plus récente de chaque type est utilisée.
2. Lancez :

```bash
ansible-playbook -i inventory/hosts.ini restore.yml -e restore_archives_dir=/chemin/vers/archives
```

**Par défaut, `restore_test_mode` vaut `true`** : le serveur restauré ne doit pas se comporter comme la production. Pas de crontab (les sauvegardes du serveur de test écraseraient les vraies archives du même jour sur le FTP et le Drive), pas d'identifiants FTP, pas d'alertes `check-services`, pas de renouvellement certbot, et `/etc/hosts` et `/etc/ssh` restent ceux de l'installation. Pour une vraie reprise après sinistre :

```bash
ansible-playbook -i inventory/hosts.ini restore.yml -e restore_archives_dir=/chemin/vers/archives -e restore_test_mode=false
```

Pour un test, mettez aussi des **identifiants FTP factices** dans `group_vars/all/vault.yml` : `site.yml` installe les tâches cron de sauvegarde avant que `restore.yml` ne les retire.

Restent à faire à la main : `claude` (connexion), `/root/.config/rclone/rclone.conf` (jeton Google et mots de passe de chiffrement, jamais sauvegardés), puis faire pointer les DNS et lancer `certbot renew --dry-run` pour une vraie reprise.

## Structure

```
ansible/
├── inventory/
│   ├── hosts.ini              # Inventaire (Ansible lancé depuis un poste de contrôle)
│   ├── local.ini              # Inventaire (Ansible lancé sur le serveur lui-même)
│   └── group_vars -> ../group_vars
├── group_vars/
│   ├── all/
│   │   ├── vars.yml           # Variables globales
│   │   └── vault.yml          # Variables sensibles (mots de passe)
│   └── dkim.yml               # Configuration DKIM
├── playbooks/
│   ├── 01-system-setup.yml    # Configuration système de base
│   ├── 02-ssh-setup.yml       # Configuration SSH
│   ├── 03-apache-setup.yml    # Installation Apache
│   ├── 04-nginx-setup.yml     # Installation Nginx
│   ├── 05-php-setup.yml       # Installation PHP
│   ├── 06-nodejs-setup.yml    # Installation NodeJS
│   ├── 07-mariadb-setup.yml   # Installation MariaDB
│   ├── 08-adminer-setup.yml   # Installation Adminer
│   ├── 09-certbot-setup.yml   # Installation Certbot
│   ├── 10-webhook-setup.yml   # Installation Webhook
│   ├── 11-mail-server.yml     # Postfix + Dovecot
│   ├── 12-rspamd-setup.yml    # Antispam (RSpamD + Redis)
│   ├── 13-dkim-setup.yml      # Configuration DKIM
│   ├── 14-ufw-setup.yml       # Firewall UFW
│   ├── 16-crowdsec-setup.yml  # CrowdSec
│   ├── 18-logrotate-setup.yml # Logrotate
│   ├── 21-backup-setup.yml    # Sauvegardes FTP
│   ├── 22-screenshot-service.yml # Service ShareX (SFTP chroot)
│   ├── 23-lynis-setup.yml     # Lynis + BIND
│   └── 24-claude-code-setup.yml # Claude Code
├── templates/                 # Templates Jinja2 pour les fichiers de config
├── site.yml                   # Playbook complet
├── restore.yml                # Restauration depuis les sauvegardes
└── minimal.yml               # Playbook minimal
```

## Important

- **Ne modifiez PAS le README.md principal**
- Les playbooks suivent le serveur réellement en production, et divergent donc du README principal sur ces points : Fail2ban (remplacé par CrowdSec), Netdata, Monit et OpenVPN ne sont plus installés (playbooks 15, 17, 19 et 20 supprimés, numérotation conservée)
- Les fichiers sensibles (mots de passe) sont dans `group_vars/all/vault.yml` qui est exclu de Git
- Après l'exécution, pensez à :
  1. Configurer vos DNS (MX, SPF, DKIM, DMARC)
  2. Générer vos certificats SSL avec Certbot
  3. Configurer vos domaines dans Apache/Nginx
  4. Créer vos comptes mail dans la base de données

## Variables importantes

| Variable | Description |
|----------|-------------|
| `server_ip` | IP publique du serveur |
| `ssh_port` | Port SSH (défaut: 2222) |
| `ssh_authorized_keys` | Clés publiques autorisées pour root (obligatoire) |
| `mail_domain` | Domaine principal pour les mails |
| `dkim_domains` | Liste des domaines avec configuration DKIM |
| `crowdsec_whitelist_ip` | IP à whitelister dans CrowdSec |

## Dépannage

Si vous rencontrez des erreurs :

1. Vérifiez la connectivité SSH : `ansible -i inventory/hosts.ini all -m ping`
2. Vérifiez la syntaxe : `ansible-playbook -i inventory/hosts.ini site.yml --syntax-check`
3. Exécutez en mode debug : `ansible-playbook -i inventory/hosts.ini site.yml -vvv`
