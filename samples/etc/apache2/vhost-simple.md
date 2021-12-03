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