```apache
# Variables
site_domain = thesite.com
site_path = /var/www/${site_domain}

# Site Global
<VirtualHost *:8085>
	ServerName ${site_domain}
	ServerAlias ${site_domain}
	ServerAdmin contact@${site_domain}

	DocumentRoot ${site_path}/site

	# WordPress Conf
	<Directory "/var/www/clients/tsuki-no-sakura/site">
		Include conf-custom/wordpress.conf

		# AuthName "Connexion"
		# AuthType Basic
		# AuthUserFile "${site_path}/.htpasswd"
		# Require valid-user
	</Directory>

	# wp-config protection
	<Files wp-config.php>
		Require all denied
	</Files>

	# Logs
	ErrorLog ${APACHE_LOG_DIR}/${site_domain}/site_error.log
	CustomLog ${APACHE_LOG_DIR}/${site_domain}/site_access.log combined
</VirtualHost>

# Base Redirect
<VirtualHost *:8085>
	ServerName ${site_domain}
	ServerAlias ${site_domain}

	Redirect permanent / https://${site_domain}
</VirtualHost>
```