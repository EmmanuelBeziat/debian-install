# debian-install
A quick stuff of my debian server config

If help is needed for one of the following commands, use https://explainshell.com/ to get more info.

# 0 Preliminary stuff

## 0.1 System update

```console
apt update
apt upgrade
apt dist-upgrade
apt autoremove
apt autoclean
```

# 1 SSH Setup

## 1.1 Add authorized keys

✏️ `/root/.ssh/authorized_keys`

If you need to generate a key, you can use PuTTyGen or the following command:

```console
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
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

**[📝 Exemple file](samples/etc/ssh/sshd_config.md)**

----------

⚙️ Restart ssh and reconnect:

```console
service ssh restart
```

# 2 General config

## 2.1 Tools

Common tools

```console
apt install -y software-properties-common gnupg2 curl wget
```

## 2.1.1 git

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

## 2.1.2 vim

```console
apt install vim
```

## 2.2 Rsync

## 2.3 Cron

## 2.4 Other

Change timezone

```console
timedatectl set-timezone Europe/Paris
```


# 3 Webserver

## 3.1 Apache2

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

✏️ `/etc/apache2/ports.conf`
```apache
# If you just change the port or add more ports here, you will likely also have to change the VirtualHost statement in /etc/apache2/sites-enabled/000-default.conf
Listen 8085

# <IfModule ssl_module>
# 	Listen 443
# </IfModule>

# <IfModule mod_gnutls.c>
# 	Listen 443
# </IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

✏️ `/etc/apache2/conf-available/charset.conf`
```apache
# Read the documentation before enabling AddDefaultCharset.
# In general, it is only a good idea if you know that all your files have this encoding. It will override any encoding given in the files in meta http-equiv or xml encoding tags.

AddDefaultCharset UTF-8

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

✏️ `/etc/apache2/conf-available/javascrip-common.conf`
```apache
Alias /javascript /usr/share/javascript/

<Directory "/usr/share/javascript/">
	Options FollowSymLinks MultiViews
</Directory>
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
a2enconf charset  javascrip-common  security
```

**Enable mods**
```console
a2enmod rewrite http2 mime ssl deflate env headers mpm_event deflate actions
```

### 3.1.3 VirtualHosts config

* **[📝 Exemple file: Vhost simple](samples/etc/apache2/vhost-simple.md)**
* **[📝 Exemple file: Vhost wordpress](samples/etc/apache2/vhost-wordpress.md)**

Then, restart the service.

```console
systemctl restart apache2
```

## 3.2 Nginx

Nginx will be used as a reverse-proxy for Apache and NodeJS. It will operate static files.

**[💡 Documentation (nginx.org)](https://nginx.org/en/docs/)**

### 3.2.1 Install

```console
apt install -y nginx
```

### 3.2.2 Configuration

✏️ `/etc/nginx/nginx.conf`
* **[📝 Exemple file](samples/etc/nginx/nginx.conf.md)**

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
    server <SERVER_IP>:<PORT_APACHE>;
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
add_header Content-Security-Policy "default-src 'self'; connect-src 'self' http: https: *.github.com api.github.com *.youtube.com; img-src 'self' data: http: https: *.gravatar.com youtube.com www.youtube.com *.youtube.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' http: https: www.google-analytics.com *.googleapis.com *.googlesynddication.com *.doubleclick.net youtube.com www.youtube.com *.youtube.com; style-src 'self' 'unsafe-inline' http: https: *.googleapis.com youtube.com www.youtube.com *.youtube.com; font-src 'self' data: http: https: *.googleapis.com *.googleuservercontent.com youtube.com www.youtube.com; child-src http: https: youtube.com www.youtube.com; base-uri 'self'; frame-ancestors 'self'";
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
```

✏️ `/etc/nginx/conf.d/webmanifest.conf`
```nginx
add_header X-Content-Type-Options nosniff;
add_header Cache-Control "max-age=31536000,immutable";
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

✏️ `/etc/nginx/snippets/favicon_error.conf`
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

✏️ `/etc/nginx/snippets/gzip-config.conf`
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

* **[📝 Exemple file: Mime types](samples/etc/nginx/mime.types.md)**


### 3.2.3 VirtualHosts config

* **[📝 Exemple file: Vhost simple](samples/etc/nginx/vhost-simple.md)**

Then, check if your config is okay and restart the service.

```console
nginx -t
systemctl restart nginx
```

## 3.3 PHP

### 3.3.1 Installation

To use php 8, a third party repository is needed. If you want to stick with php 7.4, ignore the first steps.

```console
apt -y install apt-transport-https lsb-release ca-certificates curl wget
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
apt install php8.0 php8.0-opcache libapache2-mod-php8.0 php8.0-mysql php8.0-curl php8.0-gd php8.0-intl php8.0-mbstring php8.0-xml php8.0-zip php8.0-fpm php8.0-readline php8.0-xml
php -v
```

Add a mod fof factcgi in apache.

✏️ `/etc/nginx/mods-enabled/fastcgi.conf`

```apache
<IfModule mod_fastcgi.c>
	AddHandler fastcgi-script .fcgi
	FastCgiIpcDir /var/lib/apache2/fastcgi

	AddType application/x-httpd-fastphp .php
	Action application/x-httpd-fastphp /php-fcgi
	Alias /php-fcgi /usr/lib/cgi-bin/php-fcgi
	FastCgiExternalServer /usr/lib/cgi-bin/php-fcgi -socket /run/php/php7.2-fpm.sock -pass-header Authorization

	<Directory /usr/lib/cgi-bin>
		Require all granted
	</Directory>
</IfModule>
```

And enable it.

```console
a2enmod fastcgi
```

Enable the php8.0-fpm service.

```console
a2enmod proxy_fcgi setenvif
a2enconf php8.0-fpm
a2dismod php8.0
```

Then restart Apache2.

## 3.4 NodeJS

NodeJS can be installed with the package manager, but in order to get more flexibility over the version, I prefer to use NVM (Node Version Manager).

**[💡 Documentation (github.com/nvm-sh/nvm)](https://github.com/nvm-sh/nvm)**

Download the latest installer script from the repository and run it.

```console
curl -sL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh -o install_nvm.sh
bash install_nvm.sh
source ~/.profile
nvm -v
```

Then, install the desired version of NodeJS with nvm command:

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

# 4 Databases

## 4.1 MariaDB

### 4.1.1 Install

```console
apt install mariadb-server mariadb-client
```

Run secure script to set password, remove test database and disabled remote root user login.

```console
mysql_secure_installation
```

Create an admin utilisator for external connections.

```console
mysql -u root -p
```

## 4.2 MongoDB


## 4.3 PhpMyAdmin

🔺I’ll be testing and using Adminer on my new server. The configuration shown here is for documentation purpose. Jump to next section for Adminer installation.

## 4.4 Adminer

Alternative to PhpMyAdmin, Adminer is a web-based MySQL management tool. It is a free and open-source database management tool written in PHP.

```console
wget "http://www.adminer.org/latest.php" -O /var/www/emmanuelbeziat/sql/index.php
wget "https://raw.githubusercontent.com/vrana/adminer/master/designs/dracula/adminer.css" -O /var/www/emmanuelbeziat/sql/adminer.css
chown -R www-data:www-data /var/www/emmanuelbeziat/sql
chmod -R 755 /var/www/emmanuelbeziat/sql/index.php
```

**[💡 Documentation (adminer.org)](https://www.adminer.org/)**

# 5 Letsencrypt (Certbot)

```console
apt install -y certbot
```

Commands lists:

# 6 Webhook

## 6.1 Install Go

Webhook require Go to be installed.

Go to [Go website](https://go.dev/dl/) to get the latest version.

```console
wget https://go.dev/dl/go1.17.4.linux-amd64.tar.gz
tar -xvf go1.17.4.linux-amd64.tar.gz -C /usr/local
```

Add go to PATH variable and check if it is working.

```console
export PATH=$PATH:/usr/local/go/bin
go version
```

## 6.2 Install Webhook

**[💡 Documentation (github.com/adnanh)](https://github.com/adnanh/webhook)**

```console
apt install -y webhook
```

Prepare the general config file.

✏️ `/usr/share/hooks/hooks.json`

** [📝 Example file](samples/hooks/hooks.json)**

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


# 7 Mail server

## 7.1 Postfix

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

Default rules are located in `/etc/default/ufw`.

Immediately allow your SSH port to avoid being locked out. Finally, enable UFW, and check its status.

```console
ufw allow <SSH_PORT>/tcp
ufw enable
ufw status
```

Now, proceed to add custom rules, either with `ufw allow` or `ufw deny`, on a chosen port. Alternatively, you can use `ufw allow <app>` to allow all traffic on a given application.

Use `ufw app list` to list all applications.

These applications rules are defined in `/etc/ufw/applications.d/`.

```console
ufw allow in "WWW full"


**💡 USEFUL TIP**

You can list all ufw rules with a specific number, for example to easily delete them.

```console
ufw status numbered
ufw delete <number>
```

## 8.2 Fail2ban

### 8.2.1 Installation

```console
apt get install fail2ban
```

To avoid custom rules to be erased by a new update, create a copy of the configuration file.

```console
cp /etc/fail2ban/jail.conf  /etc/fail2ban/jail.local
```

### 8.2.2 Custom configuration

✏️ `/etc/fail2ban/jail.local`

* Under `ssh`:
  * `port = <SSH_PORT>`

Then, restart the service to load the new configuration.

```console
systemctl restart fail2ban
```

# 9 FTP

# 10 Services

## 10.1 Monosnap (for screenshots)

## 10.2 VPN