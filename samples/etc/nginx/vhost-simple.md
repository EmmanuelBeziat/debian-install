```nginx
# Site
server {
    listen 443 ssl http2;
    server_name www.mysite.com;

    access_log /var/log/nginx/mysite/site_access.log;
    error_log /var/log/nginx/mysite/site_error.log info;

    include snippets/favicon_error.conf;

    location ~* ^.+.(jpg|jpeg|gif|css|png|js|ico|txt|srt|swf|woff|woff2)$ {
        root /var/www/landings/mysite/site/;
        expires 30d;
    }

    location / {
        proxy_pass http://127.0.0.1:8085/;
        include /etc/nginx/conf.d/proxy.conf;
        root /var/www/landings/mysite/site/;
    }

    ssl_certificate /etc/letsencrypt/live/mysite.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mysite.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

# Redirections
server {
    if ($host = mysite.com) {
        return 301 https://$host$request_uri;
    }

    listen 80;
    server_name mysite.com;
    return 404;
}

server {
    if ($host = www.mysite.com) {
        return 301 https://$host$request_uri;
    }

    listen 80;
    server_name www.mysite.com;
    return 404;
}
```