# debian-install
A quick stuff of my debian server config

![Debian logo](https://upload.wikimedia.org/wikipedia/commons/thumb/4/4a/Debian-OpenLogo.svg/182px-Debian-OpenLogo.svg.png)

If help is needed for one of the following commands, use https://explainshell.com/ to get more info.

# Table of Contents

- [0 Preliminary stuff](#0-preliminary-stuff)
  - [0.1 System update](#01-system-update)
- [1 SSH Setup](#1-ssh-setup)
  - [1.1 Add authorized keys](#11-add-authorized-keys)
  - [1.2 ssh config](#12-ssh-config)
- [2 General config](#2-general-config)
  - [2.1 Tools](#21-tools)
    - [2.1.1 git](#211-git)
    - [2.1.2 vim](#212-vim)
  - [2.2 Rsync](#22-rsync)
  - [2.3 Cron](#23-cron)
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
  - [3.4 NodeJS](#34-nodejs)
    - [3.4.1 Npm-check-Update](#341-npm-check-update)
    - [3.4.2 PM2](#342-pm2)
- [4 Databases](#4-databases)
  - [4.1 MariaDB](#41-mariadb)
    - [4.1.1 Install](#411-install)
  - [4.2 MongoDB](#42-mongodb)
    - [4.2.1 Install](#421-install)
    - [4.2.2 Configure](#422-configure)
  - [4.3 PhpMyAdmin](#43-phpmyadmin)
  - [4.4 Adminer](#44-adminer)
- [5 SSL and HTTPS](#5-ssl-and-https)
  - [5.1 Certbot](#51-certbot)
- [6 Webhook](#6-webhook)
  - [6.1 Install Go](#61-install-go)
  - [6.2 Install Webhook](#62-install-webhook)
    - [6.2.1 Custom service](#621-custom-service)
- [7 Mail server](#7-mail-server)
  - [7.1 Postfix](#71-postfix)
    - [7.1.1 Configure Postfix as a Forwarding System Mail](#711-configure-postfix-as-a-forwarding-system-mail)
  - [7.2 Spamassassin](#72-spamassassin)
    - [7.2.1 Installation](#721-installation)
    - [7.2.2 Configure with Postfix](#722-configure-with-postfix)
    - [7.2.3 Custom filters](#723-custom-filters)
  - [7.3 DKIM](#73-dkim)
  - [7.4 DMARC](#74-dmarc)
  - [7.5 Testing](#75-testing)
- [8 Security](#8-security)
  - [8.1 UFW](#81-ufw)
  - [8.2 Fail2ban](#82-fail2ban)
    - [8.2.1 Installation](#821-installation)
    - [8.2.2 Custom configuration](#822-custom-configuration)
    - [8.2.3 Custom filters](#823-custom-filters)
- [9 FTP](#9-ftp)
- [10 Services](#10-services)
  - [10.1 Screenshot app (Monosnap, ShareX, etc.)](#101-screenshot-app-monosnap-sharex-etc)
  - [10.2 VPN](#102-vpn)
  - [10.3 Auto saves via FTP](#103-auto-saves-via-ftp)

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
apt install -y software-properties-common gnupg2 curl wget
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

## 2.1.2 vim

![Vim logo](https://upload.wikimedia.org/wikipedia/commons/thumb/9/9f/Vimlogo.svg/240px-Vimlogo.svg.png)

Vim is a free and open-source, screen-based text editor program.

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

```console
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
add_header Content-Security-Policy "default-src 'self'; connect-src 'self' http: https: blob: *.github.com api.github.com *.youtube.com; img-src 'self' data: http: https: blob: *.gravatar.com youtube.com www.youtube.com *.youtube.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' http: https: blob: www.google-analytics.com *.googleapis.com *.googlesynddication.com *.doubleclick.net youtube.com www.youtube.com *.youtube.com; style-src 'self' 'unsafe-inline' http: https: blob: *.googleapis.com youtube.com www.youtube.com *.youtube.com; font-src 'self' data: http: https: blob: *.googleapis.com *.googleuservercontent.com youtube.com www.youtube.com; child-src http: https: blob: youtube.com www.youtube.com; base-uri 'self'; frame-ancestors 'self'";
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

To use php 8, a third party repository is needed. If you want to stick with php 7.4, ignore the first steps and replace "8.1" by "7.4".

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
apt install php8.2 php8.2-opcache libapache2-mod-php8.2 php8.2-mysql php8.2-curl php8.2-gd php8.2-intl php8.2-mbstring php8.2-xml php8.2-zip php8.2-fpm php8.2-readline php8.2-xml
php -v
```

Add a mod fof factcgi in apache.

✏️ `/etc/apache2/mods-enabled/fastcgi.conf`

```apache
<IfModule mod_fastcgi.c>
	AddHandler fastcgi-script .fcgi
	FastCgiIpcDir /var/lib/apache2/fastcgi

	AddType application/x-httpd-fastphp .php
	Action application/x-httpd-fastphp /php-fcgi
	Alias /php-fcgi /usr/lib/cgi-bin/php-fcgi
	FastCgiExternalServer /usr/lib/cgi-bin/php-fcgi -socket /run/php/php8.2-fpm.sock -pass-header Authorization

	<Directory /usr/lib/cgi-bin>
		Require all granted
	</Directory>
</IfModule>
```

And enable it.

```console
a2enmod fastcgi
```

Enable the php8.2-fpm service.

```console
a2enmod proxy_fcgi setenvif
a2enconf php8.2-fpm
a2dismod php8.2
```

⚙️ Then restart Apache2.

Once everything is working, configure your php instance.

✏️ `/etc/php/8.1/fpm/php.ini`

* `max_execution_time = 300`
* `post_max_size = 512M`
* `upload_max_filesize = 512M`
* `date.timezone = Europe/Paris`

## 3.4 NodeJS

![NodeJS Logo](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d9/Node.js_logo.svg/320px-Node.js_logo.svg.png)

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

Create an admin utilisator for external connections.

```console
mysql -u root -p
```

## 4.2 MongoDB

![MongoDB Logo](https://upload.wikimedia.org/wikipedia/commons/thumb/9/93/MongoDB_Logo.svg/320px-MongoDB_Logo.svg.png)

MongoDB is a source-available cross-platform document-oriented database program. Classified as a NoSQL database program, MongoDB uses JSON-like documents with optional schemas. MongoDB is developed by MongoDB Inc. and licensed under the Server Side Public License (SSPL).

**[💡 Documentation (mongodb.com)](https://docs.mongodb.com/manual/tutorial/getting-started/)**

### 4.2.1 Install

> 🛑 MongoDB has odd compatibility issues with CPUs. It needs AVX, which is not available on all CPUs, mostly server CPUs.
>
> If you can't use the last version, you must try with previous ones.


MongoDB must be added to package manager, and require a pgp key to do so.

/etc/apt/trusted.gpg.d

```console
wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | apt-key add -
echo "deb http://repo.mongodb.org/apt/debian buster/mongodb-org/4.4 main" | tee /etc/apt/sources.list.d/mongodb-org-4.4.list
apt update
apt install -y mongodb-org=4.4.10 mongodb-org-server=4.4.10 mongodb-org-shell=4.4.10 mongodb-org-mongos=4.4.10 mongodb-org-tools=4.4.10
```

### 4.2.2 Configure

✏️ `/etc/mongod.conf`

```yaml
net:
  port: <CUSTOM_PORT>`
```

```console
chown -R mongodb:mongodb /var/lib/mongodb
chown -R mongodb:mongodb /var/log/mongodb
```

Then, start the service.

```console
systemctl start mongod
chown mongodb:mongodb /tmp/mongodb-<CUSTOM_PORT>.sock
systemctl enable mongod
mongod --version
```

> 🛑 After installation, MongoDB is not secured at all, and can be accessed without password. It **MUST** be setup properly. 🛑

First, connect to the database and use admin database to create a new user.

```console
mongo --port <CUSTOM_PORT>
use admin
db.createUser({ user: "admin", pwd: "admin", roles: [{role: "userAdminAnyDatabase", db: "admin"}, "readWriteAnyDatabase" ]})
```

Next, configure MongoDB file configuration.

✏️ `/etc/mongod.conf`

```yaml
security:
  authorization: enabled`
```

⚙️ Then restart the service.

```console
systemctl restart mongod
```

To connect to the database, use the command:

```console
mongo --port <CUSTOM_PORT> -u mongouser -p --authenticationDatabase admin
```


## 4.3 PhpMyAdmin

🔺I’ll be testing and using Adminer on my new server. The configuration shown here is for documentation purpose. Jump to next section for Adminer installation.

## 4.4 Adminer

Alternative to PhpMyAdmin, Adminer is a web-based MySQL management tool. It is a free and open-source database management tool written in PHP.


**[💡 Documentation (adminer.org)](https://www.adminer.org/)**

```console
wget "http://www.adminer.org/latest.php" -O /var/www/emmanuelbeziat/sql/adminer.php
wget "https://raw.githubusercontent.com/vrana/adminer/master/designs/dracula/adminer.css" -O /var/www/emmanuelbeziat/sql/adminer.css
chown -R www-data:www-data /var/www/emmanuelbeziat/sql
chmod -R 755 /var/www/emmanuelbeziat/sql/adminer.php
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

**[💡 Documentation (eff-certbot.readthedocs.io)](https://eff-certbot.readthedocs.io/en/stable/using.html)**

```console
apt install -y certbot python3-certbot-nginx
```

Simply add a new domain:

```console
certbot certonly --webroot -w /var/www/mywebsite/ -d mywebsite.com -d www.mywebsite.com
```

If, at any point, this certificate needs to be expanded to include a new domain, you can use the --cert-name command (the expand command would create a -0001 version):

```console
certbot --cert-name mywebsite.com -d mywebsite.com,www.mywebsite.com,xyz.mywebsite.com
```

Renewal should be enabled by default.

# 6 Webhook

## 6.1 Install Go

![Go logo](https://upload.wikimedia.org/wikipedia/commons/thumb/0/05/Go_Logo_Blue.svg/320px-Go_Logo_Blue.svg.png)

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
/usr/bin/webhook -hooks hooks.json -secure -verbose
```

### 6.2.1 Custom service

In case webhook default service isn't providing enough flexibility, you can create a custom service.

Start by disabling the default service:

```console
systemctl disable webhook
```

Let’s create a service file:

✏️ `/opt/webhook/webhook.service`:

```bash
[Unit]
Description=Webhook Custom Service
After=network.target

[Service]
ExecStart=/usr/bin/webhook -hooks=/usr/share/hooks.json -hotreload=true -port=9000 -secure=false -verbose=true -debug=false
WorkingDirectory=/opt/webhook
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Now, it needs to be linked in `/etc/systemd/system/`:

```console
ln -s /opt/webhook/webhook.service /etc/systemd/system/mywebhook.service
systemctl daemon-reload
systemctl enable mywebhook
systemctl start mywebhook
```

Every change made will be automatically taken in account, so you don’t have to reload the configuration manually like apache or nginx.

**[💡 Documentation (github.com/adnanh/webhook/discussions/562)](https://github.com/adnanh/webhook/discussions/562)**

# 7 Mail server

This configuration will create a forwarding system to any regular mail service (like gmail).

Configure a full mail server is a pain in the ass, I highly recommand to check out [this whole guide from workaround.org](https://workaround.org/bullseye/)

First, you need to create a DNS record for your domain.

```
@ 86400 IN MX 10 yourdomain.com
```

You can also create a DNS record for SPF. For example, with google services:

```
@ 10800 IN TXT "v=spf1 +mx +a +ip4:<YOUR_IP> include:_spf.google.com ?all"
```

## 7.1 Postfix

Install Postfix (duh).

```console
apt install -y postfix
```

### 7.1.1 Configure Postfix as a Forwarding System Mail

During the install, an assistant will ask which type of mail configuration you wish to use. Chose "no configuration".

Let’s configure the main.cf file:

✏️ `/etc/postfix/main.cf`

* `myhostname = <DOMAIN>`

At the end of the file, add:

```bash
inet_protocols = all
inet_interfaces = all

virtual_alias_domains = <DOMAIN>
virtual_alias_maps = hash:/etc/postfix/virtual
alias_maps = hash:/etc/postfix/virtual
alias_database = hash:/etc/postfix/virtual
mydestination = localhost
relayhost =
mailbox_size_limit = 0
recipient_delimiter = +

# TLS parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/<DOMAIN>/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/<DOMAIN>/privkey.pem
smtp_use_tls=yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
```

Now, we need to create a `virtual` file, and add all the domains to be used as virtual mailboxes (one per line):

✏️ `/etc/postfix/virtual`

```bash
contact@<DOMAIN> <CONTACT_EMAIL>
hello@<DOMAIN> <HELLO_EMAIL>
```

⚙️ Then, you need to build the `virtual` file as a data service. Then, restart Postfix:

```console
postmap /etc/postfix/virtual
systemctl restart postfix
```

## 7.2 Spamassassin

![SpamAssassin](https://spamassassin.apache.org/images/spamassassin-logobar.png)

Start by installing Spamassassin.

```console
apt install spamassassin
```

Then, we need to create a user and a group:

```console
adduser spamassassin
```

Edit the configuration file:

✏️ `/etc/default/spamassassin`

```bash
OPTIONS="--username spamassassin --nouser-config --max-children 2 --helper-home-dir ${SAHOME} --socketowner=spamassassin --socketgroup=spamassassin --socketmode=0660"
CRON=1
```
* **[📝 Example file: Spamassassin sample](samples/etc/spamassassin/config.md)**

Lastly, create a file named `spamassassin` in `/var/spool/postfix/private`, and give it the owner postfix (110/117).

## 7.2.2 Configure with Postfix

✏️ `/etc/postfix/master.cf`

Replace line `smtp`:

```bash
smtp inet n - - - - smtpd -o content_filter=spamassassin
```

At the end, add:

```bash
spamassassin unix - n n - - pipe
user=spamassassin argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}
```

Reload configuration by restarting:

```bash
systemctl restart spamassassin
systemctl restart postfix
```

**[💡 Documentation (https://spamassassin.apache.org/)](https://spamassassin.apache.org/)**

## 7.3 DKIM

DKIM is a signature authentification for mailing. It prevent mails from ending into spam folders.

```console
apt install opendkim opendkim-tools spamass-milter
```

Let’s configure the file opendkim.conf file, by adding this at the end:

✏️ `/etc/opendkim.conf`

```bash
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   007
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes

Canonicalization        relaxed/simple

ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable

Mode                    sv
PidFile                 /run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256

UserID                  opendkim:opendkim

Socket                  inet:12301@localhost
```

Then create the folders:

```bash
mkdir /etc/opendkim
mkdir /etc/opendkim/keys
```

✏️ `/etc/default/openkimd`

```bash
smtpd_milters = unix:/spamass/spamass.sock, inet:localhost:12301
non_smtpd_milters = unix:/spamass/spamass.sock, inet:localhost:12301
```

> 🔺In the next steps, `mail` is going to be a reference to the selector. In this example, the target mail address would be `mail@yourdomain.com`. It could be changed to anything, but be sure to keep the selector of your choice and use it in replacement for `mail` in every step.

And finally, each configuration files:

✏️ `/etc/opendkim/TrustedHosts`

```console
127.0.0.1
localhost
192.168.0.1/24
*.yourdomain.com
```

✏️ `/etc/opendkim/KeyTable`

```console
mail._domainkey.yourdomain.com yourdomain.com:mail:/etc/opendkim/keys/yourdomain.com/mail.private
```

✏️ `/etc/opendkim/SigningTable`

```console
*@yourdomain.com mail._domainkey.yourdomain.com
```

When using spamassassin, change the option in spamass-milter:

✏️ `/etc/default/spamass-milter`

```bash
OPTIONS="-u spamass-milter -i 127.0.0.1 -m -I -- --socket=/var/run/spamassassin/spamd.sock"
```

Next step is generating a key pair:

```console
cd /etc/opendkim/keys
mkdir yourdomain.com
cd yourdomain.com
opendkim-genkey -s mail -d yourdomain.com
```
This will generate `mail.private` and `mail.txt`, which contains the public key you need to note.

You need to set the owner on the private file.

```console
chown opendkim:opendkim mail.private
```

Now restart opendkim to reload the configuration:

```console
systemctl restart opendkim
```

Then, you need to create a new DNS record.

```
mail._domainkey 10800 IN TXT "v=DKIM1; k=rsa; p=<YOUR_PUBLICKEY>"
```

## 7.4 DMARC

```console
apt install opendmarc
```

✏️ `/etc/opendmarc.conf`

```bash
Socket inet:54321@localhost
```

✏️ `/etc/postfix/main.cf`

```
smtpd_milters = inet:localhost:12301 inet:localhost:54321
non_smtpd_milters = inet:localhost:12301 inet:localhost:54321
```

```console
systemctl restart opendmarc
systemctl restart postfix
```

DNS:

```console
_dmarc.yourdomain.com 3600 IN TXT "v=DMARC1;p=quarantine;pct=100;rua=mailto:youradress@yourdomain.com;ruf=mailto:forensik@yourdomain.com;adkim=s;aspf=r"
```

## 7.5 Testing

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
ufw allow in "postfix"
```

⚙️ Finally, enable UFW and check its status:

```console
ufw enable
ufw status
```

If you have installed Webhook, let’s make a custom application rule:

✏️ `/etc/ufw/applications.d/webhook`

```bash
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

# 9 FTP

# 10 Services

## 10.1 Screenshot app (Monosnap, ShareX, etc.)

![ShareX Logo](https://upload.wikimedia.org/wikipedia/commons/d/d1/ShareX_Logo.png)

The point here is to define an access for a screenshot app to upload files in a specific directory via sftp.

Start by creating a new user:

```console
adduser screenshot
```

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

## 10.3 Auto saves via FTP
