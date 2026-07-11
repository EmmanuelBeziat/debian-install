# Debian Server Ansible Playbooks

Automatisation complète de l'installation d'un serveur Debian avec Ansible, basée sur le guide [debian-install](../README.md).

## Prérequis

- Ansible 2.9+
- Accès SSH root au serveur Debian
- Une clé SSH configurée dans `~/.ssh/authorized_keys` du serveur

## Installation

### 1. Configuration

Copiez les fichiers d'exemple et modifiez-les avec vos propres valeurs :

```bash
cd ansible
cp group_vars/all.yml.example group_vars/all.yml
cp group_vars/vault.yml.example group_vars/vault.yml
```

### 2. Configuration des variables

Éditez `group_vars/all.yml` avec vos paramètres :

```yaml
server_ip: "VOTRE_IP_SERVEUR"
server_hostname: "votre_hostname"
ssh_port: 2222
mail_domain: "votre-domaine.com"
admin_email: "admin@votre-domaine.com"
crowdsec_whitelist_ip: "VOTRE_IP_ADMIN"
```

Éditez `group_vars/vault.yml` avec vos mots de passe :

```yaml
mariadb_root_password: "MOT_DE_PASSE_ROOT"
mail_db_password: "MOT_DE_PASSE_MAIL"
mariadb_admin_password: "MOT_DE_PASSE_ADMIN"
ftp_host: "ftp.example.com"
ftp_user: "backup_user"
ftp_password: "MOT_DE_PASSE_FTP"
```

### 3. Configuration de l'inventaire

Éditez `inventory/hosts.ini` :

```ini
[servers]
debian-server ansible_host=YOUR_SERVER_IP ansible_user=root

[servers:vars]
ansible_python_interpreter=/usr/bin/python3
```

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
ansible-playbook -i inventory/hosts.ini playbooks/15-fail2ban-setup.yml
ansible-playbook -i inventory/hosts.ini playbooks/16-crowdsec-setup.yml
```

## Structure

```
ansible/
├── inventory/
│   └── hosts.ini              # Inventaire des serveurs
├── group_vars/
│   ├── all.yml                # Variables globales
│   ├── vault.yml              # Variables sensibles (mots de passe)
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
│   ├── 15-fail2ban-setup.yml  # Fail2ban
│   ├── 16-crowdsec-setup.yml  # CrowdSec
│   ├── 17-netdata-setup.yml   # Netdata monitoring
│   ├── 18-logrotate-setup.yml # Logrotate
│   ├── 19-monit-setup.yml     # Monit + alertes
│   ├── 20-vpn-setup.yml       # OpenVPN
│   └── 21-backup-setup.yml    # Sauvegardes FTP
├── templates/                 # Templates Jinja2 pour les fichiers de config
├── site.yml                   # Playbook complet
└── minimal.yml               # Playbook minimal
```

## Important

- **Ne modifiez PAS le README.md principal**
- Les fichiers sensibles (mots de passe) sont dans `group_vars/vault.yml` qui est exclu de Git
- Après l'exécution, pensez à :
  1. Ajouter vos clés SSH à `/root/.ssh/authorized_keys`
  2. Configurer vos DNS (MX, SPF, DKIM, DMARC)
  3. Générer vos certificats SSL avec Certbot
  4. Configurer vos domaines dans Apache/Nginx
  5. Créer vos comptes mail dans la base de données

## Variables importantes

| Variable | Description |
|----------|-------------|
| `server_ip` | IP publique du serveur |
| `ssh_port` | Port SSH (défaut: 2222) |
| `mail_domain` | Domaine principal pour les mails |
| `dkim_domains` | Liste des domaines avec configuration DKIM |
| `crowdsec_whitelist_ip` | IP à whitelister dans CrowdSec |

## Dépannage

Si vous rencontrez des erreurs :

1. Vérifiez la connectivité SSH : `ansible -i inventory/hosts.ini all -m ping`
2. Vérifiez la syntaxe : `ansible-playbook -i inventory/hosts.ini site.yml --syntax-check`
3. Exécutez en mode debug : `ansible-playbook -i inventory/hosts.ini site.yml -vvv`
