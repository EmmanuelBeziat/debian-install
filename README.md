# debian-install
A quick stuff of my debian server config

![Debian logo](https://upload.wikimedia.org/wikipedia/commons/thumb/4/4a/Debian-OpenLogo.svg/182px-Debian-OpenLogo.svg.png)

If help is needed for one of the following commands, use https://explainshell.com/ to get more info.

# Table of Contents

- [0 Preliminary stuff](#0-preliminary-stuff)
  - [0.1 System update](#01-system-update)
  - [0.2 System upgrade](#02-system-upgrade)
- [1 SSH Setup](#1-ssh-setup)
  - [1.1 Add authorized keys](#11-add-authorized-keys)
  - [1.2 ssh config](#12-ssh-config)
- [2 General config](#2-general-config)
  - [2.1 Tools](#21-tools)
    - [2.1.1 git](#211-git)
    - [2.1.2 vim](#212-vim)
	- [2.1.3 dos2unix](#213-dos2unix)
  - [2.2 Rsync](#22-rsync)
  - [2.3 Cron](#23-cron)
    - [2.3.1 Usual cron tasks](#231-usual-cron-tasks)
  - [2.4 Other](#24-other)
- [3 Webserver](#3-webserver)
  - [3.1 Apache2](#31-apache2)
    - [3.1.1 Install](#311-install)
    - [3.1.2 Configuration](#312-configuration)
    - [3.1.3 VirtualHosts config](#313-virtualhosts-config)
  - [3.2 Nginx](#32-nginx)
    - [3.2.1 Install](#321-install)
    - [3.2.2 Configuration](#322-configuration)
    - [3.2.3 VirtualHosts config](#323-virtualhosts-config)
  - [3.3 PHP](#33-php)
    - [3.3.1 Installation](#331-installation)
    - [3.3.2 Composer](#332-composer)
  - [3.4 NodeJS](#34-nodejs)
    - [3.4.1 Npm-check-Update](#341-npm-check-update)
    - [3.4.2 PM2](#342-pm2)
	- [3.4.3 Update Script](#343-update-script)
- [4 Databases](#4-databases)
  - [4.1 MariaDB](#41-mariadb)
    - [4.1.1 Install](#411-install)
	- [4.1.2 Create admin user](#412-create-admin-user)
  - [4.2 Adminer](#44-adminer)
- [5 SSL and HTTPS](#5-ssl-and-https)
  - [5.1 Certbot](#51-certbot)
- [6 Webhook](#6-webhook)
  - [6.1 Install Go](#61-install-go)
  - [6.2 Install Webhook](#62-install-webhook)
    - [6.2.1 Custom service](#621-custom-service)
- [7 Mail server](#7-mail-server)
  - [7.1 Postfix](#71-postfix)
    - [7.1.1 Configure Postfix as a Forwarding System Mail](#711-configure-postfix-as-a-forwarding-system-mail)
  - [7.2 Dovecot](#72-dovecot)
  - [7.3 RSpamD](#73-rspamd)
    - [7.3.1 Configure with Postfix](#731-configure-with-postfix)
  - [7.4 DKIM](#74-dkim)
  - [7.5 DMARC](#75-dmarc)
  - [7.6 Automatic Certificate renewal](#76-automatic-renewal-of-certificate)
  - [7.7 Testing](#77-testing)
    - [7.7.1 Useful tools](#771-useful-tools)
- [8 Security](#8-security)
  - [8.1 UFW](#81-ufw)
  - [8.2 Fail2ban](#82-fail2ban)
    - [8.2.1 Installation](#821-installation)
    - [8.2.2 Custom configuration](#822-custom-configuration)
    - [8.2.3 Custom filters](#823-custom-filters)
  - [8.3 CrowdSec](#83-crowdsec)
    - [8.3.1 Installation](#831-installation)
    - [8.3.2 Configuration](#832-configuration)
    - [8.3.3 Usage](#833-usage)
    - [8.3.4 Secure Access](#834-secure-acccess)
- [9 Monitoring et Logs](#9-monitoring-et-logs)
  - [9.1 Netdata](#91-netdata)
    - [9.1.1 Installation](#911-installation)
    - [9.1.2 Configuration](#912-configuration)
    - [9.1.3 Nginx Reverse Proxy](#913-nginx-reverse-proxy)
    - [9.1.4 Custom Alerts](#914-custom-alerts)
  - [9.2 Logrotate](#92-logrotate)
    - [9.2.1 Installation](#921-installation)
    - [9.2.2 Configuration](#922-configuration)
    - [9.2.3 Test Configuration](#923-test-configuration)
  - [9.3 Alertes Système](#93-alertes-systeme)
    - [9.3.1 Installation de Monit](#931-installation-de-monit)
    - [9.3.2 Configuration Monit](#932-configuration-monit)
    - [9.3.3 Scripts d'Alerte Personnalisés](#933-scripts-dalerte-personnalises)
    - [9.3.4 Configuration des Tâches Cron](#934-configuration-des-taches-cron)
    - [9.3.5 Démarrage des Services](#935-demarrage-des-services)
  - [9.4 Logs Centralisés (Optionnel)](#94-logs-centralises-optionnel)
    - [9.4.1 Installation de rsyslog](#941-installation-de-rsyslog)
    - [9.4.2 Configuration rsyslog](#942-configuration-rsyslog)
    - [9.4.3 Rotation des Logs Système](#943-rotation-des-logs-systeme)
- [10 FTP](#10-ftp)
- [10 Services](#10-services)
  - [10.1 Screenshot app (Monosnap, ShareX, etc.)](#101-screenshot-app-monosnap-sharex-etc)
  - [10.2 VPN](#102-vpn)
    - [10.2.1 Installation](#1021-installation)
	- [10.2.2 Add user](#1022-add-users)
  - [10.3 Auto saves via FTP](#103-auto-saves-via-ftp)
    - [10.3.1 Install LFTP](#1031-install-lftp)
	- [10.3.2 Preparing credentials](#1032-preparing-credentials)
	- [10.3.3 Make Scripts](#1033-make-sripts)

# 0 Preliminary stuff

## 0.1 System update

```console
apt update
apt upgrade
apt dist-upgrade
apt autoremove
apt autoclean
```

## 0.2 System upgrade

If needed, upgrade the debian version.

Update the source-list file:

✏️ `/etc/apt/sources.list`

Change the sources by upgrading the version name.

```
deb http://mirrors.online.net/debian bullseye main non-free contrib
deb-src http://mirrors.online.net/debian bullseye main non-free contrib

deb http://security.debian.org/debian-security bullseye-security main contrib non-free
deb-src http://security.debian.org/debian-security bullseye-security main contrib non-free
```

```
deb http://mirrors.online.net/debian bookworm main non-free-firmware
deb-src http://mirrors.online.net/debian bookworm main non-free-firmware

deb http://security.debian.org/debian-security bookworm-security main non-free-firmware
deb-src http://security.debian.org/debian-security bookworm-security main non-free-firmware
```

Then update packages.

```console
apt update
apt upgrade --without-new-pkgs
apt full-upgrade
dpkg -l 'linux-image*' | grep ^ii | grep -i meta
apt install
```

Then, reboot the system.

```console
reboot
```

When back online, purge obsolete packages.

```console
apt autoremove --purge
apt autoclean
apt clean
apt purge '~c'
apt purge '~o'
```

Check the version.

```console
lsb_release -a
```

# 1 SSH Setup

## 1.1 Add authorized keys

✏️ `/root/.ssh/authorized_keys`

If you need to generate a key, you can use PuTTyGen or the following command:

```console
ssh-keygen -t ed25519 -C "your_email@example.com"
```

## 1.2 ssh config

✏️ `/etc/ssh/sshd_config`

Configuration:

* `Port <Change to whatever>`
* `PermitRootLogin prohibit-password`
* `PubkeyAuthentication yes`
* `PasswordAuthentication no`
* `PermitEmptyPasswords no`
* `ChallengeResponseAuthentication no`
* `UsePAM no`
* `X11Forwarding no`
* `PrintMotd no`
* `UseDNS no`
* `AcceptEnv LANG LC_*`

**[📝 Example file](samples/etc/ssh/sshd_config.md)**

----------

⚙️ Restart ssh and reconnect:

```console
service ssh restart
```

# 2 General config

## 2.1 Tools

Common tools

```console
apt install -y software-properties-common gnupg2 curl wget zip unzip dos2unix jq
```

## 2.1.1 git

![Git logo](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e0/Git-logo.svg/320px-Git-logo.svg.png)

Git will be used to manage websites from github repositories.

Install:

```console
apt install -y git
git --version
```

Setting:

```console
git config --global user.name "Your name"
git config --global user.email "your@email.com"
git config --global core.editor "vim"
```

**[💡 Documentation (git-scm.com)](https://git-scm.com/book/fr/v2/Personnalisation-de-Git-Configuration-de-Git)**

Add github

## 2.1.2 vim

![Vim logo](https://upload.wikimedia.org/wikipedia/commons/thumb/9/9f/Vimlogo.svg/240px-Vimlogo.svg.png)

Vim is a free and open-source, screen-based text editor program.

```console
apt install vim
```

## 2.1.3 dos2unix

When transferring files made in windows on the server, it might create errors. Install dos2unix to rewrite faulted files.

```console
apt install dos2unix
```

How to use:

```console
dos2unix /path/to/file
```

## 2.2 Rsync

## 2.3 Cron

### 2.3.1 Usual cron tasks

**Remove old logs**
```console
crontab -e
```

```bash
0 12 * * * /snap/bin/certbot renew --quiet
0 12 * * * apt update
0 12 * * * find /var/log -name "*.1" -type f -delete
0 12 * * * /usr/bin/find /var/log -type f -name '*.log' -mtime +2 -exec rm {} \;
```

## 2.4 Other

Change timezone

```console
timedatectl set-timezone Europe/Paris
```

# 3 Webserver

## 3.1 Apache2

![Apache Logo](https://upload.wikimedia.org/wikipedia/commons/thumb/1/10/Apache_HTTP_server_logo_%282019-present%29.svg/480px-Apache_HTTP_server_logo_%282019-present%29.svg.png)

Apache 2.4 will operate PHP

**[💡 Documentation (httpd.apache.org)](https://httpd.apache.org/)**

### 3.1.1 Install

```console
apt install -y apache2
```

Check its status:

```console
systemctl status apache2
```

Ensure that the service will be started at boot:

```console
systemctl enable apache2
```

### 3.1.2 Configuration

Let’s start by create a custom set of defined constants.

✏️ `/etc/apache2/conf-custom/constants.conf`

```apache
Define APACHE_PORT 8085
```

Then include it in the main configuration file.

✏️ `/etc/apache2/apache2.conf`

```apache
# Global configuration
#

include conf-custom/constants.conf
```

Now, the defined constants can be called within any Apache configuration file.

✏️ `/etc/apache2/ports.conf`
```apache
# If you just change the port or add more ports here, you will likely also have to change the VirtualHost statement in /etc/apache2/sites-enabled/000-default.conf
Listen ${APACHE_PORT}

# <IfModule ssl_module>
# 	Listen 443
# </IfModule>

# <IfModule mod_gnutls.c>
# 	Listen 443
# </IfModule>
```

✏️ `/etc/apache2/conf-available/charset.conf`
```apache
# Read the documentation before enabling AddDefaultCharset.
# In general, it is only a good idea if you know that all your files have this encoding. It will override any encoding given in the files in meta http-equiv or xml encoding tags.

AddDefaultCharset UTF-8
```

✏️ `/etc/apache2/conf-available/security.conf`
* `ServerTokens Prod`
* `ServerSignature Off`
* `TraceEnable Off`

✏️ `/etc/apache2/conf-custom/wordpress.conf`
```apache
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteBase /
	RewriteRule ^index\.php$ - [L]
	RewriteCond %{REQUEST_FILENAME} !-f
	RewriteCond %{REQUEST_FILENAME} !-d
	RewriteRule . /index.php [L]
</IfModule>
```

**Enable configurations**

```console
a2enconf charset security
```

**Enable mods**
```console
a2enmod rewrite http2 mime ssl deflate env headers mpm_event deflate actions
```

### 3.1.3 VirtualHosts config

* **[📝 Example file: Vhost simple](samples/etc/apache2/vhost-simple.md)**
* **[📝 Example file: Vhost wordpress](samples/etc/apache2/vhost-wordpress.md)**

⚙️ Then, restart the service.

```console
systemctl restart apache2
```

## 3.2 Nginx

![Nginx Logo](https://upload.wikimedia.org/wikipedia/commons/thumb/c/c5/Nginx_logo.svg/320px-Nginx_logo.svg.png)

Nginx will be used as a reverse-proxy for Apache and NodeJS. It will operate static files.

**[💡 Documentation (nginx.org)](https://nginx.org/en/docs/)**

### 3.2.1 Install

By default, the Nginx version is tied to the Debian release. To force upgrade to the latest version, add the repository to the source list.

To avoid any odd issue, you may install the "native" version first:

```console
apt install -y nginx
```

```console
curl -fsSL https://nginx.org/keys/nginx_signing.key | tee /etc/apt/trusted.gpg.d/nginx_signing.asc
echo "deb https://nginx.org/packages/mainline/debian/ $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list
apt update
apt install -y nginx
```

### 3.2.2 Configuration

✏️ `/etc/nginx/nginx.conf`
* **[📝 Example file](samples/etc/nginx/nginx.conf.md)**

✏️ `/etc/nginx/conf.d/cache.conf`
```nginx
add_header Cache-Control "public, max-age=31536000, immutable";
```

✏️ `/etc/nginx/conf.d/charset.conf`
```nginx
map $sent_http_content_type $charset {
    default '';
    ~^text/ utf-8;
    text/css utf-8;
    application/javascript utf-8;
    application/rss+xml utf-8;
    application/json utf-8;
    application/manifest+json utf-8;
    application/geo+json utf-8;
}

charset $charset;
charset_types *;
```

✏️ `/etc/nginx/conf.d/default.conf`
```nginx
upstream apachephp {
    server <SERVER_IP>:<APACHE_PORT>;
}

server {
    charset utf-8;
    source_charset utf-8;
    override_charset on;
    server_name localhost;
}
```

✏️ `/etc/nginx/conf.d/headers.conf`
```nginx
# add_header X-Frame-Options "SAMEORIGIN";
# add_header X-XSS-Protection "1;mode=block";
add_header X-Content-Type-Options nosniff;
add_header Cache-Control "public, immutable";
add_header Strict-Transport-Security "max-age=500; includeSubDomains; preload;";
add_header Referrer-Policy origin-when-cross-origin;
add_header Content-Security-Policy "default-src 'self'; connect-src 'self' http: https: blob: ws: *.github.com api.github.com *.youtube.com; img-src 'self' data: http: https: blob: *.gravatar.com youtube.com www.youtube.com *.youtube.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' http: https: blob: www.google-analytics.com *.googleapis.com *.googlesynddication.com *.doubleclick.net youtube.com www.youtube.com *.youtube.com; style-src 'self' 'unsafe-inline' http: https: blob: *.googleapis.com youtube.com www.youtube.com *.youtube.com; font-src 'self' data: http: https: blob: *.googleapis.com *.googleuservercontent.com youtube.com www.youtube.com; child-src http: https: blob: youtube.com www.youtube.com; base-uri 'self'; frame-ancestors 'self'";
```

✏️ `/etc/nginx/conf.d/proxy.conf`
```nginx
proxy_redirect			off;
proxy_set_header		Host		$host;
proxy_set_header		X-Real-IP	$remote_addr;
proxy_set_header		X-Forwarded-For	$proxy_add_x_forwarded_for;

client_max_body_size		10m;
client_body_buffer_size		128k;
proxy_connect_timeout		90;
proxy_send_timeout		90;
proxy_read_timeout		90;
proxy_buffer_size		16k;
proxy_buffers			32	16k;
proxy_busy_buffers_size		64k;

proxy_hide_header      Upgrade;
```

✏️ `/etc/nginx/conf.d/webmanifest.conf`
```nginx
add_header X-Content-Type-Options nosniff;
add_header Cache-Control "max-age=31536000,immutable";
```

✏️ `/etc/nginx/conf.d/gzip.conf`
```nginx
types {
	application/x-font-ttf           ttf;
	font/opentype                    ott;
}

gzip on;
gzip_disable "msie6";
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_min_length 256;
gzip_buffers 16 8k;
gzip_http_version 1.1;
#gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

# Compress all output labeled with one of the following MIME-types.
gzip_types
application/atom+xml
application/javascript
application/json
application/ld+json
application/manifest+json
application/rss+xml
application/vnd.geo+json
application/vnd.ms-fontobject
application/x-font-ttf
application/x-web-app-manifest+json
application/xhtml+xml
application/xml
font/opentype
image/bmp
image/svg+xml
image/x-icon
text/cache-manifest
text/css
text/plain
text/vcard
text/vnd.rim.location.xloc
text/vtt
text/x-component
text/x-cross-domain-policy;
# text/html is always compressed by gzip module
# don't compress woff/woff2 as they're compressed already
```


✏️ `/etc/nginx/snippets/cache.conf`
```nginx
add_header Cache-Control "public, no-transform";
```

✏️ `/etc/nginx/snippets/expires.conf`
```nginx
map $sent_http_content_type $expires {
	default off;
	text/html epoch;
	text/css max;
	application/javascript max;
	~image/ max;
}
```

✏️ `/etc/nginx/snippets/favicon-error.conf`
```nginx
location = /favicon.ico {
    access_log off;
    log_not_found off;
}
location = /robots.txt {
    return 204;
    access_log off;
    log_not_found off;
}
```

✏️ `/etc/nginx/snippets/ssl-config.conf`
```nginx
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

# Dropping SSL and TLSv1
ssl_prefer_server_ciphers on;
ssl_ciphers "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
ssl_ecdh_curve secp384r1;
ssl_dhparam /etc/ssl/certs/dhparam.pem;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# Cache credentials
ssl_session_timeout 1h;

# Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 208.67.222.222 valid=300s;
resolver_timeout 5s;
```

✏️ `/etc/nginx/mime.types`

* **[📝 Example file: Mime types](samples/etc/nginx/mime.types.md)**


### 3.2.3 VirtualHosts config

* **[📝 Example file: Vhost simple](samples/etc/nginx/vhost-simple.md)**

⚙️ Then, check if your config is okay and restart the service.

```console
nginx -t
systemctl restart nginx
```

## 3.3 PHP

![PHP](https://upload.wikimedia.org/wikipedia/commons/thumb/2/27/PHP-logo.svg/320px-PHP-logo.svg.png)

### 3.3.1 Installation

To use php 8, a third party repository is needed. If you want to stick with php 7.4, ignore the first steps and replace "8.4" by "7.4".

```console
apt -y install apt-transport-https lsb-release ca-certificates
wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
sh -c 'echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list'
```

Then update php and check if php 8 is available for installation.

```console
apt update
apt-cache policy php
```

If everything is reay, install the version of php you need, then check if it's installed correctly.

```console
apt install php8.4 php8.4-opcache libapache2-mod-php8.4 php8.4-mysql php8.4-curl php8.4-gd php8.4-intl php8.4-mbstring php8.4-xml php8.4-zip php8.4-fpm php8.4-readline php8.4-xml
php -v
```

Add a mod for factcgi in apache.

✏️ `/etc/apache2/mods-enabled/fastcgi.conf`

```apache
<IfModule mod_fastcgi.c>
	AddHandler fastcgi-script .fcgi
	FastCgiIpcDir /var/lib/apache2/fastcgi

	AddType application/x-httpd-fastphp .php
	Action application/x-httpd-fastphp /php-fcgi
	Alias /php-fcgi /usr/lib/cgi-bin/php-fcgi
	FastCgiExternalServer /usr/lib/cgi-bin/php-fcgi -socket /run/php/php8.4-fpm.sock -pass-header Authorization

	<Directory /usr/lib/cgi-bin>
		Require all granted
	</Directory>
</IfModule>
```

And enable it.

```console
a2enmod fastcgi
```

Enable the php8.4-fpm service.

```console
a2enmod proxy_fcgi setenvif
a2enconf php8.4-fpm
a2dismod php8.4
```

⚙️ Then restart Apache2.

Once everything is working, configure your php instance.

✏️ `/etc/php/8.4/fpm/php.ini`

* `max_execution_time = 300`
* `post_max_size = 512M`
* `upload_max_filesize = 512M`
* `date.timezone = Europe/Paris`

### 3.3.2 Composer

Now that php is available in the command line, install composer

```console
curl -sS https://getcomposer.org/installer | php
```

Add it to global path:

```console
mv composer.phar /usr/local/bin/composer
chmod +x /usr/local/bin/composer
```

## 3.4 NodeJS

![NodeJS Logo](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d9/Node.js_logo.svg/320px-Node.js_logo.svg.png)

NodeJS can be installed with the package manager, but in order to get more flexibility over the version, I prefer to use NVM (Node Version Manager).

**[💡 Documentation (github.com/nvm-sh/nvm)](https://github.com/nvm-sh/nvm)**

Download the latest installer script from the repository and run it.

```console
curl -sL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh -o install_nvm.sh
bash install_nvm.sh
source ~/.profile
nvm -v
```

Then, install the latest version of NodeJS with nvm command:
```console
nvm install node
nvm use node
nvm alias node
```

Or a specific version:

```console
nvm ls-remote
nvm install v17.2.0
nvm use v17.2.0
nvm alias default 17.2.0
```

NPM should have been installed with NodeJS. It can be updated right away with the command:

```console
npm i -g npm@latest
```

### 3.4.1 Npm-check-Update

Check for outdated, incorrect and unused dependencies, globally or locally.

**[💡 Documentation (github.com/npm/npm-check-updates)](https://www.npmjs.com/package/npm-check-updates)**

```console
npm install -g npm-check-updates
```

### 3.4.2 PM2

PM2 is a production process manager for Node.js applications with a built-in load balancer. It allows you to keep applications alive forever, to reload them without downtime and to facilitate common system admin tasks.

**[💡 Documentation (npmjs.com)](https://www.npmjs.com/package/pm2)**

```console
npm install pm2 -g
```

Once it has been started, we need to make sure it restart automatically with each reboot.

```console
pm2 startup
```

When a process is started with pm2, save a list of currently active processes so it’s restored on reboot.

```console
pm2 save
```

If needed, a save can be loaded manually.

```console
pm2 restore
```

## 3.4.3 Update script

NVM has an issue: updating the version will not keep your globally installed packages. Here’s a script to make this automatically:

✏️ `/usr/local/bin/node-update`
```bash
#!/bin/bash

# Step 1: Save list of global npm packages
echo "Saving the list of global npm packages…"
GLOBAL_PACKAGES=$(npm list -g --depth=0 --json | jq -r '.dependencies | keys[]')
echo "Global npm packages saved: $GLOBAL_PACKAGES"

# Step 2: Save PM2 processes
echo "Saving PM2 process list…"
pm2 save
echo "PM2 processes saved."

# Step 3: Load nvm environment
echo "Loading nvm…"
export NVM_DIR="$HOME/.nvm"
if [ -s "$NVM_DIR/nvm.sh" ]; then
  . "$NVM_DIR/nvm.sh"
  echo "nvm loaded successfully."
else
  echo "Error: nvm not found. Please install nvm and try again."
  exit 1
fi

# Step 4: Fetch and install the latest Node.js version
echo "Fetching the latest Node.js version…"
LATEST_VERSION=$(nvm ls-remote | grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+' | tail -n 1)
if [ -z "$LATEST_VERSION" ]; then
  echo "Error: Unable to fetch the latest Node.js version. Exiting."
  exit 1
fi
echo "Latest Node.js version fetched: $LATEST_VERSION"
echo "Installing Node.js version $LATEST_VERSION…"
nvm install "$LATEST_VERSION"

# Step 5: Set the latest Node.js version as default
echo "Setting Node.js version $LATEST_VERSION as the default version…"
nvm use "$LATEST_VERSION"
nvm alias default "$LATEST_VERSION"
echo "Default Node.js version set to $LATEST_VERSION."

# Step 6: Reinstall global npm packages
echo "Reinstalling global npm packages…"
for package in $GLOBAL_PACKAGES; do
  echo "Installing $package…"
  npm install -g "$package"
done
echo "Global npm packages reinstalled."

# Step 7: Reinstall PM2 globally
echo "Reinstalling PM2…"
npm install -g pm2
echo "PM2 reinstalled."

# Step 8: Resurrect PM2 processes
echo "Resurrecting PM2 processes…"
pm2 resurrect
echo "PM2 processes resurrected."

# Step 9: Final Confirmation
echo "Node.js update process completed successfully!"
echo "Installed Node.js version: $(node -v)"
```

Make it executable:

```console
chmod +x /usr/local/bin/node-update
```

To use it, just call:

```console
node-update
```

# 4 Databases

## 4.1 MariaDB

![Maria DB Logo](https://upload.wikimedia.org/wikipedia/commons/thumb/c/ca/MariaDB_colour_logo.svg/320px-MariaDB_colour_logo.svg.png)

MariaDB Server is one of the most popular open source relational databases. It’s made by the original developers of MySQL and guaranteed to stay open source. It is part of most cloud offerings and the default in most Linux distributions.

It is built upon the values of performance, stability, and openness, and MariaDB Foundation ensures contributions will be accepted on technical merit. Recent new functionality includes advanced clustering with Galera Cluster 4, compatibility features with Oracle Database and Temporal Data Tables, allowing one to query the data as it stood at any point in the past.

**[💡 Documentation (mariadb.org)](https://mariadb.org/documentation/)**

### 4.1.1 Install

```console
apt install mariadb-server mariadb-client
```

Run secure script to set password, remove test database and disabled remote root user login.

```console
mysql_secure_installation
```
### 4.1.2 Create admin user

Create an admin utilisator for external connections.

```console
mysql -u root -p
CREATE USER 'user'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'user'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

## 4.2 Adminer

Alternative to PhpMyAdmin, Adminer is a web-based MySQL management tool. It is a free and open-source database management tool written in PHP.


**[💡 Documentation (adminer.org)](https://www.adminer.org/)**

```console
wget "http://www.adminer.org/latest.php" -O /var/www/mywebsite/adminer.php
wget "https://raw.githubusercontent.com/vrana/adminer/master/designs/dracula/adminer.css" -O /var/www/mywebsite/adminer.css
chown -R www-data:www-data /var/www/mywebsite
chmod -R 755 /var/www/mywebsite/adminer.php
```

To add plugins, create an index file in the same directory:

```php
function adminer_object() {
    // required to run any plugin
    include_once './plugins/plugin.php';

    // autoloader
    foreach (glob("plugins/*.php") as $filename) {
        include_once "./$filename";
    }

    $plugins = [
        // specify enabled plugins here
	];

    /* It is possible to combine customization and plugins:
    class AdminerCustomization extends AdminerPlugin {
    }
    return new AdminerCustomization($plugins);
    */

    return new AdminerPlugin($plugins);
}

// include original Adminer or Adminer Editor
include './adminer.php';
```

# 5 SSL and HTTPS

![Letsencrypt logo](https://upload.wikimedia.org/wikipedia/en/thumb/0/07/Let%27s_Encrypt.svg/320px-Let%27s_Encrypt.svg.png)

Create SSL certificates for virtualhosts.

## 5.1 Certbot

Preliminary, it is needed to install [the package manager snap (snapcraft.io)](https://snapcraft.io/docs/installing-snap-on-debian), as it’s now the preferred way of installing certbot.

```console
apt install snapd
snap install snapd
```

**[💡 Documentation (eff-certbot.readthedocs.io)](https://eff-certbot.readthedocs.io/en/stable/using.html)**

```console
snap install --classic certbot
ln -s /snap/bin/certbot /usr/bin/certbot
```

Simply add a new domain:

```console
certbot certonly --nginx -d mywebsite.com -d www.mywebsite.com -d cdn.mywebsite.com
```

This will automatically change the vhost file. To make it manually, use the command without the `--nginx` flag.

If, at any point, this certificate needs to be expanded to include a new domain, you can use the --cert-name command (the expand command would create a -0001 version):

```console
certbot --cert-name mywebsite.com -d mywebsite.com,www.mywebsite.com,xyz.mywebsite.com
```

And to remove a certificate:

```console
certbot delete --cert-name mywebsite.com
```

Renewal should be enabled by default.

# 6 Webhook

## 6.1 Install Go

![Go logo](https://upload.wikimedia.org/wikipedia/commons/thumb/0/05/Go_Logo_Blue.svg/320px-Go_Logo_Blue.svg.png)

Webhook require Go to be installed.

Go to [Go website](https://go.dev/dl/) to get the latest version.

```console
wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
tar -xvf go1.25.0.linux-amd64.tar.gz -C /usr/local
```

Add go to PATH variable and check if it is working.

```console
export PATH=$PATH:/usr/local/go/bin
go version
```

## 6.2 Install Webhook

**[💡 Documentation (github.com/adnanh)](https://github.com/adnanh/webhook)**

```console
snap install webhook
ln -s /snap/webhook/current/bin/webhook /usr/bin/webhook
```

Prepare the general config file.

✏️ `/usr/share/hooks/hooks.json`

* **[📝 Example file](samples/hooks/hooks.md)**

Add the script to be executed by the hooks

✏️ `/usr/share/hooks/mywebsite/deploy.sh`

```bash
#!/bin/bash

exec > /usr/share/hooks/mywebsite/output.log 2>&1

git fetch --all
git checkout --force "origin/main"
```

Then make it executable.

```console
chmod +x /usr/share/hooks/mywebsite/deploy.sh
```

⚙️ Run webhook with:

```console
/usr/bin/webhook -hooks /usr/share/hooks/hooks.json -secure -verbose
```

### 6.2.1 Custom service

In case webhook default service isn't providing enough flexibility, you can create a custom service.

Start by disabling the default service:

```console
systemctl disable webhook
```

Let’s create a service file:

✏️ `/opt/webhook/webhook.service`:

```apache
[Unit]
Description=Webhook Custom Service
After=network.target

[Service]
ExecStart=/usr/bin/webhook -hooks=/usr/share/hooks/hooks.json -hotreload=true -ip "127.0.0.1" -port=9000 -verbose=true
WorkingDirectory=/opt/webhook
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Now, it needs to be linked in `/etc/systemd/system/`. Be sure not to call it just "webhook.service", because it would conflict with another service:

```console
ln -s /opt/webhook/webhook.service /etc/systemd/system/go-webhook.service
systemctl daemon-reload
systemctl enable go-webhook
systemctl start go-webhook
```

Every change made will be automatically taken in account, so you don’t have to reload the configuration manually like apache or nginx.

**[💡 Documentation (github.com/adnanh/webhook/discussions/562)](https://github.com/adnanh/webhook/discussions/562)**

# 7 Mail server

This configuration will create a full mailing system, with users, aliases and antispam, using mysql.

First, you need to create a DNS record for your domain.

```
@ 86400 IN MX 10 yourdomain.com
```

You can also create a DNS record for SPF. For example, with google services:

```
@ 10800 IN TXT "v=spf1 +mx +a +ip4:<YOUR_IP> include:_spf.google.com ?all"
```

## 7.1 Install Postfix and Dovecot

Install Postfix and it's extension for using it with mysql. Postfix will handle SMTP.

```console
apt install -y postfix postfix-mysql
```

During the install, an assistant will ask which type of mail configuration you wish to use. Chose "no configuration".

Dovecot will store received mails and provide IMAP access for users.

```bash
apt install -y dovecot-core dovecot-mysql dovecot-pop3d dovecot-imapd dovecot-managesieved dovecot-lmtpd
```

## 7.2 Preparing the database

Connect to mysql to create a database.

```bash
mysql -u root -p
CREATE DATABASE mailserver;
```

Then, we’ll need to create a specific user with readonly rights to check the email addresses. Here, it will be named `mailserver` too. To prevent issues with access, use `127.0.0.1` instead of `localhost`.

```bash
CREATE USER 'mailserver'@'127.0.0.1' IDENTIFIED BY 'password';
GRANT SELECT ON mailserver.* TO 'mailserver'@'127.0.0.1';
FLUSH PRIVILEGES;
```

Next, create databases :

```sql
USE mailserver;

CREATE TABLE IF NOT EXISTS `virtual_domains` (
 `id` int(11) NOT NULL auto_increment,
 `name` varchar(50) NOT NULL,
 PRIMARY KEY (`id`)
 ) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `virtual_users` (
 `id` int(11) NOT NULL auto_increment,
 `domain_id` int(11) NOT NULL,
 `email` varchar(100) NOT NULL,
 `password` varchar(150) NOT NULL,
 `quota` bigint(11) NOT NULL DEFAULT 0,
 PRIMARY KEY (`id`),
 UNIQUE KEY `email` (`email`),
 FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
 ) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `virtual_aliases` (
 `id` int(11) NOT NULL auto_increment,
 `domain_id` int(11) NOT NULL,
 `source` varchar(100) NOT NULL,
 `destination` varchar(100) NOT NULL,
 PRIMARY KEY (`id`),
 FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
 ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

## 7.2.1 Configure Postfix

✏️ `/etc/postfix/conf/mysql-virtual-mailbox-domains.cf`

```apache
user = mailserver
password = password
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s'
```

Now, add the configuration line to `/etc/postfix/main.cf` with this command. Then, test it with `postmap`.

```console
postconf virtual_mailbox_domains=mysql:/etc/postfix/conf/mysql-virtual-mailbox-domains.cf
postmap -q mywebsite.com mysql:/etc/postfix/conf/mysql-virtual-mailbox-domains.cf
```

It should return `1`.

Then, create the mapping for mailboxes.

✏️ `/etc/postfix/conf/mysql-virtual-mailbox-maps.cf`

```apache
user = mailserver
password = password
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s'
```

And the mapping for aliases.

✏️ `/etc/postfix/conf/mysql-virtual-alias-maps.cf`


```apache
user = mailserver
password = password
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual\_aliases WHERE source='%s'
```

Then add the config lines.

```console
postconf virtual_mailbox_maps=mysql:/etc/postfix/conf/mysql-virtual-mailbox-maps.cf
postconf virtual_alias_maps=mysql:/etc/postfix/conf/mysql-virtual-alias-maps.cf
postmap -q alias@mywebsite.com mysql:/etc/postfix/conf/mysql-virtual-alias-maps.cf
```

The alias should return the mail it refers to.

Finally, create a file that will handle the catch all of aliases.

✏️ `/etc/postfix/conf/mysql-email2email.cf`

```apache
user = mailserver
password = password
hosts = 127.0.0.1
dbname = mailserver
query = SELECT email FROM virtual_users WHERE email='%s'
```

```console
postconf virtual_alias_maps=mysql:/etc/postfix/conf/mysql-virtual-email2email.cf
postmap -q alias@mywebsite.com mysql:/etc/postfix/conf/mysql-virtual-alias-maps.cf
```

It should return the same address.

Lastly, configure postfix to check all aliases.

```console
postconf virtual_alias_maps=mysql:/etc/postfix/conf/mysql-virtual-alias-maps.cf,mysql:/etc/postfix/conf/mysql-virtual-email2email.cf
```

And now, secure the files so only postfix can reach it, since it contains passwords in clear.

```console
chgrp postfix /etc/postfix/conf/mysql-*.c
chmod u=rw,g=r,o= /etc/postfix/conf/mysql-*.cf
```

Lastly, make Postfix listen to IPv6 too.

```console
postconf -e 'inet_protocols = all'
```

## 7.2.2 Configure Dovecot

Start by creating a new user with group id 5000 that will own all virtual mailboxes.

```console
groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /var/mail/vhosts -m
chown -R vmail:vmail /var/mail/vhosts
```

Now there will be a few changes made to files in `/etc/dovecot/conf.d` folder.

✏️ `10-auth.conf`

```apache
disable_plaintext_auth = no
auth_mechanisms = plain login

# !include auth-system.conf.ext
!include auth-sql.conf.ext
#!include auth-ldap.conf.ext
#!include auth-passwdfile.conf.ext
#!include auth-checkpassword.conf.ext
#!include auth-static.conf.ext
```

✏️ `10-mail.conf`

```apache
mail_location = maildir:/var/mail/vhosts/%d/%n/Maildir

#...
separator = .
#...
```

✏️ `10-master.conf`

```apache
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    group = postfix
    mode = 0600
    user = postfix
  }
}
#...
service auth {
  # Postfix smtp-auth
	unix_listener /var/spool/postfix/private/auth {
		mode = 0660
		user = postfix
		group = postfix
	}
}
```

✏️ `10-ssl.conf`

```apache
ssl = required

ssl_cert = </etc/letsencrypt/live/mywebsite.com/fullchain.pem
ssl_key = </etc/letsencrypt/live/mywebsite.com/privkey.pem
```

✏️ `10-ssl.conf`

```apache
ssl = required

ssl_cert = </etc/letsencrypt/live/mywebsite.com/fullchain.pem
ssl_key = </etc/letsencrypt/live/mywebsite.com/privkey.pem
```

Now, in the root folder of Dovecot.

✏️ `/etc/dovecot/dovecot-sql.conf.ext`

```apache
driver = mysql
default_pass_scheme = BLF-CRYP

connect = \
  host=127.0.0.1 \
  dbname=mailserver \
  user=mailserver \
  password=password

user_query = SELECT email as user, \
  concat('*:bytes=', quota) AS quota_rule, \
  '/var/mail/vhosts/%d/%n' AS home, \
  5000 AS uid, 5000 AS gid \
  FROM virtual_users WHERE email='%u'

password_query = SELECT password FROM virtual_users WHERE email='%u'

iterate_query = SELECT email AS user FROM virtual_users
```

Now, set permissions:

```console
chown root:root /etc/dovecot/dovecot-sql.conf.ext
chmod go= /etc/dovecot/dovecot-sql.conf.ext
```

Finally, restart Dovecot.

```console
systemctl restart dovecot
```

### 7.2.3 Set Postfix to send emails to Dovecot via LMTP

```console
postconf virtual_transport=lmtp:unix:private/dovecot-lmtp
```

✏️ `/etc/dovecot/conf.d/20-lmtp.conf`

```apache
protocol lmtp {
  # Space separated list of plugins to load (default is global mail_plugins).
  mail_plugins = $mail_plugins sieve
}
```

Restart Dovecot to enable configuration, and check if Postfix configuration is clear.

```console
systemctl restart dovecot
postfix check
```

### 7.2.4 Testing email delivery

Install swaks.

```console
apt install swaks -y
```

In a second console, use the command:

```console
swaks --to mail@mywebsite.com --server localhost
```

### 7.2.5 Authentication and encryption

Enable SMTP authentification so that Postfix can communicate with Dovecot throught a socket.

```console
postconf smtpd_sasl_type=dovecot
postconf smtpd_sasl_path=private/auth
postconf smtpd_sasl_auth_enable=yes
```

```console
postconf smtp_tls_security_level = may
postconf smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
postconf smtpd_tls_security_level = may
postconf smtpd_tls_cert_file = /etc/letsencrypt/live/mywebsite.com/fullchain.pem
postconf smtpd_tls_key_file = /etc/letsencrypt/live/mywebsite.com/privkey.pem
postconf smtpd_tls_auth_only = yes
```

✏️ `/etc/postfix/master.cf`

```apache
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=
  -o smtpd_helo_restrictions=
  -o smtpd_sender_restrictions=
  -o smtpd_relay_restrictions=
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_sender_restrictions=reject_sender_login_mismatch,permit_sasl_authenticated,reject
```

## 7.3 RSpamD & Redis

![RSpamD](https://docs.rspamd.com/img/rspamd_logo_navbar.png)

Start by installing RSpamD and Redis.

```console
apt install rspamd redis
```

Configure Postfix so it uses it to pass mail through RSpamD filters.

```
postconf smtpd_milters=inet:127.0.0.1:11332
postconf non_smtpd_milters=inet:127.0.0.1:11332
postconf milter_mail_macros="i {mail_addr} {client_addr} {client_name} {auth_authen}"
```

### 7.3.1 Flag spam

To make sure that spam mails are treated as such, they must get a flag.

✏️ `/etc/rspamd/override.d/milter_headers.conf`

```apache
extended_spam_headers = true;
```

You can test RSpamD configuration with this command:

```console
rspamadm configtest
```

And restart it to get the new configuration.

```console
systemctl restart rspamd
```

Then, Dovecot must be configured to read these filters and transfer them to the spam folder.

✏️ `/etc/dovecot/conf.d/90-sieve.conf`

```apache
sieve_after = /etc/dovecot/sieve-after
```

Create said folder:

```console
mkdir /etc/dovecot/sieve-after
```

And add a new file in it:

✏️ `/etc/dovecot/sieve-after/spam-to-folder.sieve`

```nginx
require ["fileinto"];

if header :contains "X-Spam" "Yes" {
 fileinto "Junk";
 stop;
}
```

Then compile it so that Dovecot can read it.:

```console
sievec /etc/dovecot/sieve-after/spam-to-folder.sieve
```

### 7.3.2 Learning

Now, configure Redis so that it persist data.

✏️ `/etc/rspamd/override.d/redis.conf`

```apache
servers = "127.0.0.1";
```

And enable autolearn.

✏️ `/etc/rspamd/override.d/classifier-bayes.conf`

```apache
autolearn = [-5, 10];
```

To enable learning from user actions, make a few changes in Dovecot.

✏️ `/etc/dovecot/conf.d/20-imap.conf`

```apache
mail_plugins = $mail_plugins quota imap_sieve
```

✏️ `/etc/dovecot/conf.d/90-sieve.conf`

```apache
# From elsewhere to Junk folder
imapsieve_mailbox1_name = Junk
imapsieve_mailbox1_causes = COPY
imapsieve_mailbox1_before = file:/etc/dovecot/sieve/learn-spam.sieve

# From Junk folder to elsewhere
imapsieve_mailbox2_name = *
imapsieve_mailbox2_from = Junk
imapsieve_mailbox2_causes = COPY
imapsieve_mailbox2_before = file:/etc/dovecot/sieve/learn-ham.sieve

sieve_pipe_bin_dir = /etc/dovecot/sieve
sieve_global_extensions = +vnd.dovecot.pipe
sieve_plugins = sieve_imapsieve sieve_extprograms
```

Then create a new folder:

```console
mkdir /etc/dovecot/sieve
```
And new files:

✏️ `/etc/dovecot/sieve/learn-spam.sieve`

```bash
require ["vnd.dovecot.pipe", "copy", "imapsieve"];
pipe :copy "rspamd-learn-spam.sh";
```


✏️ `/etc/dovecot/sieve/learn-ham.sieve`

```bash
require ["vnd.dovecot.pipe", "copy", "imapsieve", "variables"];
if string "${mailbox}" "Trash" {
  stop;
}
pipe :copy "rspamd-learn-ham.sh";
```

Compile the files:

```console
sievec /etc/dovecot/sieve/learn-spam.sieve
sievec /etc/dovecot/sieve/learn-ham.sieve
```

Finally, create two bash files:

✏️ `/etc/dovecot/sieve/rspamd-learn-spam.sh`

```bash
#!/bin/sh
exec /usr/bin/rspamc learn_spam
```

✏️ `/etc/dovecot/sieve/rspamd-learn-ham.sh`

```bash
#!/bin/sh
exec /usr/bin/rspamc learn_ham
```

Make them executable:

```console
chmod u=rwx,go= /etc/dovecot/sieve/rspamd-learn-{spam,ham}.sh
chown vmail:vmail /etc/dovecot/sieve/rspamd-learn-{spam,ham}.sh
```

And restart Dovecot.

### 7.3.3 Autoexpunge

Dovecot can remove emails in Junk folder after they reach a certain age.

✏️ `/etc/dovecot/conf.d/15-mailboxes.conf`

```bash
mailbox Junk {
  special_use = \Junk
  auto = subscribe
  autoexpunge = 30d
}
mailbox Trash {
  special_use = \Trash
  auto = subscribe
  autoexpunge = 30d
}
```

Finally, restart Dovecot and RSpamD.

```console
systemctl restart dovecot rspamd
```

## 7.4 DKIM

DKIM is a signature authentification for mailing. It prevent mails from ending into spam folders.

```console
mkdir /var/lib/rspamd/dkim
chown _rspamd:_rspamd /var/lib/rspamd/dkim
```

### 7.4.1 Prepare records

Create a new private key.

```console
rspamadm dkim_keygen -d mywebsite.com -s customkey
```

Then, you need to create a new DNS record.

```
customkey._domainkey 10800 IN TXT "v=DKIM1; k=rsa; p=<YOUR_PUBLICKEY>"
```

### 7.4.2 Mapping in RSpamD

✏️ `/etc/rspamd/local.d/dkim_signing.conf`

```apache
path = "/var/lib/rspamd/dkim/$domain.$selector.key";
selector_map = "/etc/rspamd/dkim_selectors.map";
```

✏️ `/etc/rspamd/dkim_selectors.map`

```apache
mywebsite.com customkey
```

Create a file that will store the private key created earlier.

✏️ `/var/lib/rspamd/dkim/mywebsite.com.customkey.key`

And make sure that RSpamD y a accès.

```console
chown _rspamd /var/lib/rspamd/dkim/*
chmod u=r,go= /var/lib/rspamd/dkim/*
```

Then, restart RSpamD.

```console
systemctl restart rspamd
```

## 7.5 SPF & DMARC


DNS:

```console
@ 14400 IN TXT "v=spf1 mx a ptr ip4:<server ip> include:_spf.google.com ~all"
```

```console
_dmarc.mywebsite.com 3600 IN TXT "v=DMARC1;p=quarantine;pct=100;rua=mailto:mail@mywebsite.com;ruf=mailto:forensik@mywebsite.com;adkim=s;aspf=r"
```

## 7.6 Automatic renewal of certificate

Postfix and Dovecot are not always looking for the latest ssl certificate after a renewal. To keep them up to date, restart both services using a hook post-renewal of certbox.

✏️ `/etc/letsencrypt/renewal-hooks/post/restart-mail.sh`:
```bash
#!/bin/bash
systemctl restart postfix dovecot
```

Make it executable:

```console
chmod +x /etc/letsencrypt/renewal-hooks/post/restart-mail.sh
```

## 7.7 Testing

### 7.7.1 Useful tools

```console
apt install dnsutils mailutils
```

A few tools to test your mail configuration:

* The commands `dig TXT yourdomain` to check your SPF entry, and `dig contact._domainkey.yourdomain.com TXT` to check your DKIM.
* [DKIMcore](https://dkimcore.org/c/keycheck)
* [Google Admin Tookbox CheckMX](https://toolbox.googleapps.com/apps/checkmx/)
* [MXToolbox](https://mxtoolbox.com/SuperTool.aspx)
* [MailTester](https://www.mail-tester.com/)

# 8 Security

## 8.1 UFW

UFW is a firewall that provides a simple, easy-to-use interface for managing network.

```console
apt install ufw
```

🔺 UFW is NOT enabled by default, to avoid being locked out the server. To check the status, use:

```concole
ufw status
```

Default rules are located in `/etc/default/ufw`. Applications rules are defined in `/etc/ufw/applications.d/`.

🛑 Let’s start by allow your SSH port to avoid being locked out. There must be a rule for SSH. Use `ufw app list` to list all applications.

if not, let’s create it:

✏️ `/etc/ufw/applications.d/openssh-server`:

```bash
[OpenSSH]
title=Secure shell server, an rshd replacement
description=OpenSSH is a free implementation of the Secure Shell protocol.
ports=<SSH_PORT>/tcp
```

If it exist, **<ins>be sure to change the SSH port</ins>**. Then add it to the active rules:

```console
ufw allow in "OpenSSH"
```

Now, proceed to add other needed rules, either with `ufw allow` or `ufw deny`, on a chosen port. Alternatively, you can use `ufw allow <app>` to allow all traffic on a given application.

```console
ufw allow in "WWW full"
ufw allow in "Mail submission"
ufw allow in "SMTP"
ufw allow in "SMTPS"
ufw allow in "IMAP"
ufw allow in "IMAPS
ufw allow in "POP3"
ufw allow in "POP3S"
```

⚙️ Finally, enable UFW and check its status:

```console
ufw enable
ufw status
```

If you have installed Webhook, let’s make a custom application rule (but it's not necessary if nginx receives the request and pass it directly):

✏️ `/etc/ufw/applications.d/webhook`

```apache
[Webhook]
title=Webhook Service
description=Lightweight configurable tool written that allows you to easily create HTTP endpoints
ports=<WEBHOOK_PORT>/tcp
```

Ufw usually reload after adding a new rule. Check the status, and reload if needed.

**💡 USEFUL TIP**

You can list all ufw rules with a specific number, for example to easily delete them.

```console
ufw status numbered
ufw delete <number>
```

## 8.2 Fail2ban

Fail2Ban is an intrusion prevention software framework that will lock IP out of the server.

### 8.2.1 Installation

```console
apt install fail2ban
```

To avoid custom rules to be erased by a new update, create a copy of the configuration file.

```console
cp /etc/fail2ban/jail.conf  /etc/fail2ban/jail.local
```

### 8.2.2 Custom configuration

✏️ `/etc/fail2ban/jail.local`

* Under `[DEFAULT]` section, change / add the following parameters:
  * `bantime = 5h`
  * `findtime = 20m`
  * `maxretry = 5`
  * `ignoreip = 127.0.0.1/8 ::1`
  * `banaction = ufw`
  * `banaction_allports = ufw`

* Under `[sshd]`:
  * `port = <SSH_PORT>`
  * `enabled = true`

* Under `[POSTFIX]` (if installed):
  * `port = <SMTP_PORT>`
  * `enabled = true`
  * `mode = aggressive`

⚙️ Then, restart the service to load the new configuration and check its status.

```console
systemctl restart fail2ban
fail2ban-client status
fail2ban-client status sshd
```

⚙️ If everything works fine, enable the service at startup:

```console
systemctl enable fail2ban.service
```

### 8.2.3 Custom filters

If you want to use custom filters with fail2ban it's possible by creating new files in `/etc/fail2ban/filter.d/`.

## 8.3 CrowdSec

<img src="https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/crowdsec_logo.png" alt="CrowdSec" title="CrowdSec" width="400" height="260"/>

CrowdSec is an Alternative to Fail2Ban, that relies on participative security with crowdsourced protection against ip

### 8.3.1 Installation

```console
curl -sL https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
apt install crowdsec -y
```

Check that it works:

```console
systemctl status crowdsec
```

### 8.3.2 Configuration

**Integration with UFW**

Install dependency for integration with UFW:

```console
apt install crowdsec-firewall-bouncer-iptables -y
```

Then enable it:

```console
cscli bouncers add ufw-bouncer
```

And check if it works:

```console
cscli bouncers list
```

**Watching services**

```console
cscli collections install crowdsecurity/nginx
cscli collections install crowdsecurity/postfix
systemctl restart crowdsec
```

### 8.3.3 Usage

Check the logs:

```console
cscli metrics
```

Check banned IPs:

```console
cscli decisions list
```

Lock a specific IP:

```console
cscli decisions add --ip XX.XX.XX.XX --duration 24h --scope ip --type ban --reason "IP malveillante"
```

Lock a specific IP range:

```console
cscli decisions add --range XX.XX.XX.0/24 --duration 24h --scope range --type ban --reason "Réseau malveillant"
```

Unlock a specific IP:

```console
cscli decisions delete --ip <IP>
```

### 8.3.4 Secure acccess

To avoid being locked out, whitelist a safe IP.

✏️ `/etc/crowdsec/parsers/s02-enrich/custom-whitelist.yaml`

```yaml
name: crowdsecurity/custom-whitelist
description: "Whitelist IP sécurité"
whitelist:
  reason: "IP de sécurité"
  ip:
    - XX.XX.XX.XX
```

Then restart CrowdSec and check if the IP is correctly whitelisted:

```console
systemctl restart crowdsec
cscli decisions list
```

# 9 Monitoring et Logs

## 9.1 Netdata

![Netdata Logo](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Netdata_logo.svg/320px-Netdata_logo.svg.png)

Netdata is a real-time performance monitoring tool that provides insights into real-time metrics from systems, applications, and services.

**[💡 Documentation (netdata.cloud)](https://docs.netdata.cloud/)**

### 9.1.1 Installation

Install Netdata using the official installation script:

```console
bash <(curl -Ss https://my-netdata.io/kickstart.sh) --stable-channel --disable-telemetry
```

The installation script will automatically:
- Install all dependencies
- Compile and install Netdata
- Create a systemd service
- Configure basic monitoring

### 9.1.2 Configuration

Netdata is accessible by default on port 19999. To secure access, configure authentication:

✏️ `/etc/netdata/netdata.conf`

```ini
[global]
    hostname = your-server-name
    memory mode = dbengine
    page cache size = 256
    dbengine multihost disk space = 256

[web]
    bind to = 127.0.0.1:19999
    allow connections from = 127.0.0.1
    allow connections from = ::1
    allow connections from = <YOUR_IP>/32
```

### 9.1.3 Nginx Reverse Proxy

To access Netdata through your domain, add a location block to your Nginx configuration:

✏️ `/etc/nginx/sites-available/netdata`

```nginx
server {
    listen 80;
    server_name monitoring.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:19999;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Enable the site and restart Nginx:

```console
ln -s /etc/nginx/sites-available/netdata /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

### 9.1.4 Custom Alerts

Create custom alert configurations:

✏️ `/etc/netdata/health.d/cpu.conf`

```yaml
template: 10min_cpu_usage
      on: system.cpu
    calc: $user + $system
   every: 10s
    warn: $this > (($status >= $WARNING)  ? (80) : (90))
    crit: $this > (($status == $CRITICAL) ? (90) : (95))
   delay: up 1m down 5m
    info: average cpu utilization for the last 10 minutes
      to: sysadmin
```

✏️ `/etc/netdata/health.d/disk.conf`

```yaml
template: disk_usage
      on: disk.space
   every: 1m
    warn: $this < 20
    crit: $this < 10
   delay: up 1m down 5m
    info: disk space usage
      to: sysadmin
```

## 9.2 Logrotate

Logrotate is a system utility that manages the automatic rotation and compression of log files.

### 9.2.1 Installation

Logrotate is usually pre-installed on Debian systems. If not:

```console
apt install logrotate
```

### 9.2.2 Configuration

Create custom logrotate configurations for your services:

✏️ `/etc/logrotate.d/nginx`

```bash
/var/log/nginx/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 `cat /var/run/nginx.pid`
        fi
    endscript
}
```

✏️ `/etc/logrotate.d/apache2`

```bash
/var/log/apache2/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        if /etc/init.d/apache2 status > /dev/null ; then \
            /etc/init.d/apache2 reload > /dev/null; \
        fi;
    endscript
}
```

✏️ `/etc/logrotate.d/mysql`

```bash
/var/log/mysql/*.log {
    daily
    rotate 7
    missingok
    compress
    create 640 mysql adm
    postrotate
        if test -x /usr/bin/mysqladmin && \
           /usr/bin/mysqladmin ping -h localhost --silent; then
            /usr/bin/mysqladmin flush-logs
        fi
    endscript
}
```

✏️ `/etc/logrotate.d/fail2ban`

```bash
/var/log/fail2ban.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload fail2ban
    endscript
}
```

### 9.2.3 Test Configuration

Test your logrotate configuration:

```console
logrotate -d /etc/logrotate.conf
```

Force a rotation:

```console
logrotate -f /etc/logrotate.d/nginx
```

## 9.3 Alertes Système

### 9.3.1 Installation de Monit

Monit is a utility for monitoring and managing daemon processes or similar programs running on Unix systems.

```console
apt install monit
```

### 9.3.2 Configuration Monit

✏️ `/etc/monit/monitrc`

```bash
set daemon 60
set logfile /var/log/monit.log
set idfile /var/lib/monit/id
set statefile /var/lib/monit/state

# Email alerts
set mailserver localhost
set mail-format {
  from: monit@yourdomain.com
  subject: $SERVICE $EVENT at $DATE
  message: Monit $ACTION $SERVICE at $DATE on $HOST: $DESCRIPTION.
}
set alert admin@yourdomain.com

# Web interface
set httpd port 2812 and
  use address 127.0.0.1
  allow 127.0.0.1
  allow <YOUR_IP>/32

# Check system resources
check system $HOSTNAME
  if loadavg (1min) > 4 then alert
  if loadavg (5min) > 2 then alert
  if memory usage > 80% then alert
  if cpu usage (user) > 80% then alert
  if cpu usage (system) > 80% then alert

# Check services
check process nginx with pidfile /var/run/nginx.pid
  start program = "/etc/init.d/nginx start"
  stop program = "/etc/init.d/nginx stop"
  if failed host 127.0.0.1 port 80 then restart
  if 5 restarts within 5 cycles then timeout

check process apache2 with pidfile /var/run/apache2/apache2.pid
  start program = "/etc/init.d/apache2 start"
  stop program = "/etc/init.d/apache2 stop"
  if failed host 127.0.0.1 port 8085 then restart
  if 5 restarts within 5 cycles then timeout

check process mysql with pidfile /var/run/mysqld/mysqld.pid
  start program = "/etc/init.d/mysql start"
  stop program = "/etc/init.d/mysql stop"
  if failed host 127.0.0.1 port 3306 then restart
  if 5 restarts within 5 cycles then timeout

check process fail2ban with pidfile /var/run/fail2ban/fail2ban.pid
  start program = "/etc/init.d/fail2ban start"
  stop program = "/etc/init.d/fail2ban stop"
  if 5 restarts within 5 cycles then timeout

# Check disk space
check device rootfs with path /
  if space usage > 80% then alert
  if inode usage > 80% then alert

# Check SSL certificate expiration
check file ssl_cert with path /etc/letsencrypt/live/yourdomain.com/fullchain.pem
  if changed timestamp then alert
```

### 9.3.3 Scripts d'Alerte Personnalisés

Create custom alert scripts:

✏️ `/usr/local/bin/disk-alert.sh`

```bash
#!/bin/bash

# Disk space alert script
THRESHOLD=80
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')

if [ "$DISK_USAGE" -gt "$THRESHOLD" ]; then
  echo "WARNING: Disk usage is ${DISK_USAGE}%" | \
  mail -s "Disk Space Alert on $(hostname)" admin@yourdomain.com
fi
```

✏️ `/usr/local/bin/ssl-expiry-check.sh`

```bash
#!/bin/bash

# SSL certificate expiry check
DOMAIN="yourdomain.com"
DAYS_WARNING=30

EXPIRY_DATE=$(openssl x509 -enddate -noout -in /etc/letsencrypt/live/$DOMAIN/fullchain.pem | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
CURRENT_EPOCH=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_EPOCH - $CURRENT_EPOCH) / 86400 ))

if [ "$DAYS_LEFT" -lt "$DAYS_WARNING" ]; then
  echo "WARNING: SSL certificate for $DOMAIN expires in $DAYS_LEFT days" | \
  mail -s "SSL Certificate Expiry Alert" admin@yourdomain.com
fi
```

Make scripts executable:

```console
chmod +x /usr/local/bin/disk-alert.sh
chmod +x /usr/local/bin/ssl-expiry-check.sh
```

### 9.3.4 Configuration des Tâches Cron

Add monitoring tasks to crontab:

```console
crontab -e
```

```bash
# Monitoring tasks
0 */6 * * * /usr/local/bin/disk-alert.sh
0 8 * * 1 /usr/local/bin/ssl-expiry-check.sh
0 2 * * * /usr/bin/find /var/log -name "*.log" -mtime +30 -delete
```

### 9.3.5 Démarrage des Services

Enable and start monitoring services:

```console
systemctl enable monit
systemctl start monit
systemctl enable netdata
systemctl start netdata
```

Check status:

```console
systemctl status monit
systemctl status netdata
monit status
```

## 9.4 Logs Centralisés (Optionnel)

### 9.4.1 Installation de rsyslog

For centralized logging:

```console
apt install rsyslog
```

### 9.4.2 Configuration rsyslog

✏️ `/etc/rsyslog.conf`

```bash
# Add at the end of the file
# Send all logs to a central server (replace with your log server IP)
*.* @logserver.yourdomain.com:514
```

### 9.4.3 Rotation des Logs Système

✏️ `/etc/logrotate.d/rsyslog`

```bash
/var/log/syslog
/var/log/mail.info
/var/log/mail.warn
/var/log/mail.err
/var/log/mail.log
/var/log/daemon.log
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/lpr.log
/var/log/cron.log
/var/log/debug
/var/log/messages
{
  rotate 4
  weekly
  missingok
  notifempty
  compress
  delaycompress
  sharedscripts
  postrotate
    /usr/lib/rsyslog/rsyslog-rotate
  endscript
}
```

# 10 FTP

# 10 Services

## 10.1 Screenshot app (Monosnap, ShareX, etc.)

![ShareX Logo](https://upload.wikimedia.org/wikipedia/commons/d/d1/ShareX_Logo.png)

The point here is to define an access for a screenshot app to upload files in a specific directory via sftp.

Start by creating a new user:

```console
adduser screenshot
```

Do NOT create it without a home, it wouldn’t be able to connect in SFTP.

Let’s allow the user to connect to ssh with a password. Edit the ssh config file and add the following at the end:

✏️ `/etc/ssh/sshd_config`

```bash
# Example of overriding settings on a per-user basis
Match User screenshot
	PasswordAuthentication yes
```

⚙️ Restart ssh

```console
service ssh restart
```

Now you just need to give the user access to the directory where the files will be uploaded:

```console
chown -R screenshot:screenshot /path/to/folder/
```

## 10.2 VPN

### 10.2.1 Installation

Install OpenVPN

```console
curl -O https://raw.githubusercontent.com/Angristan/openvpn-install/master/openvpn-install.sh
chmod +x openvpn-install.sh
./openvpn-install.sh
```
The script will setup and ask for questions.

Add the ports defined to UFW. For example, with a custom script:

✏️ `/etc/ufw/applications.d/openvpn`

```bash
[OpenVPN]
title=OpenVPN Service
description=Open Source VPN
ports=1194/udp
```

```console
ufw allow in "OpenVPN"
```

### 10.2.2 Add users

The script will add a first user. To add another one, reexecute the script and select the choice "Add a new user".
```console
./openvpn-install.sh
```

Configuration files (`*.ovpn`) are written in `/root/`.

## 10.3 Auto saves via FTP

### 10.3.1 Install lftp

```console
apt install lftp
```

### 10.3.2 Preparing credentials

In order not to write plain text mariadb credentials in scripts, create a file in `/root`:

✏️ `/root/.my.cnf`
```apache
[client]
user = your_mysql_user
password = your_mysql_password
host = localhost
```

Then, secure it:

```console
chmod 600 /root/.my.cnf
```

Same way, create a file to store the ftp credentials in `/root`. Be sure there is no space and no empty line, it seem to make the parsing fail.

✏️ `/root/.ftp_credentials`

```apache
host=host
user=user
password=password
```

Make sure it’s correctly encoded and secure it:

```console
dos2unix /root/.ftp_credentials
chmod 600 /root/.ftp_credentials
```
### 10.3.3 Make scripts

✏️ `/opt/backups/backup-db.sh`

* **[📝 Example file: backup-db.sh](samples/scripts/backup-db.md)**

✏️ `/opt/backups/backup-config.sh`

* **[📝 Example file: backup-config.sh](samples/scripts/backup-config.md)**

✏️ `/opt/backups/backup-sites.sh`

* **[📝 Example file: backup-sites.sh](samples/scripts/backup-sites.md)**

Make them excutable:

```console
chown +x /opt/backups/*
```

Each script can be executed manually. Let’s automate it:

```console
crontab -e
```

```bash
0 0 */2 * * /opt/backups/backup-db.sh >> /var/log/backups.log 2>&1
0 0 1 */3 * /opt/backups/backup-sites.md >> /var/log/backups.log 2>&1
0 0 1 */6 * /opt/backups/backup-config.md >> /var/log/backups.log 2>&1
```
