```bash
#!/bin/bash

# Check for zip command
command -v zip >/dev/null 2>&1 || { echo "zip command is required but it's not installed. Aborting." >&2; exit 1; }

# Define variables
DATE=$(date +'%Y.%m.%d')
ARCHIVE_NAME="/var/backups/server/${DATE}_conf-files.zip"

# Load FTP credentials
FTP_HOST=$(grep 'host=' /root/.ftp_credentials | cut -d '=' -f2 | xargs)
FTP_USER=$(grep 'user=' /root/.ftp_credentials | cut -d '=' -f2 | xargs)
FTP_PASS=$(grep 'password=' /root/.ftp_credentials | cut -d '=' -f2 | xargs)

echo "FTP_HOST: $FTP_HOST"
echo "FTP_USER: $FTP_USER"
echo "FTP_PASS: $FTP_PASS"

# List of configuration files and directories to back up
CONFIG_FILES=(
    "/etc/apache2/main.cf"
    "/etc/apache2/ports.conf"
    "/etc/apache2/conf-available/"
    "/etc/apache2/conf-custom/"
    "/etc/apache2/sites-available/"
    "/etc/dovecot/"
    "/etc/nginx/nginx.conf"
    "/etc/nginx/snippets/"
    "/etc/nginx/conf.d/"
    "/etc/nginx/sites-available/"
    "/etc/letsencrypt/"
    "/etc/postfix/main.cf"
    "/etc/postfix/master.cf"
    "/etc/postfix/conf/"
    "/etc/redis/"
    "/etc/rspamd/local.d/"
    "/etc/rspamd/override.d/"
    "/etc/rspamd/dkim_selectors.map"
    "/etc/sshd/sshd_config"
    "/etc/rspamd/"
    "/etc/ufw/applications.d/"
    "/etc/hosts"
    "/usr/share/hooks/"
    "/opt/"
    "/root/.ssh/"
    "/root/.ftp_credentials"
    "/root/.gitconfig"
    "/root/.my.cnf"
    "/var/lib/rspamd/dkim/"
)

# Maximum file size parameter (e.g., 1024m for 1024 MB); leave empty for no limit
MAX_SIZE="${1:-}"

# Create a temporary directory for organized backup structure
TMP_DIR=$(mktemp -d)

# Build rsync options based on MAX_SIZE
RSYNC_OPTS=("--relative" "-av")
[ -n "$MAX_SIZE" ] && RSYNC_OPTS+=("--max-size=$MAX_SIZE")

# Copy files while preserving directory structure in temporary directory
for CONFIG_FILE in "${CONFIG_FILES[@]}"; do
    rsync "${RSYNC_OPTS[@]}" "$CONFIG_FILE" "$TMP_DIR"
done

# Change to the temporary directory to ensure zip archives contents directly
cd "$TMP_DIR" || exit

# Create the archive from the contents of TMP_DIR
zip -r "$ARCHIVE_NAME" ./*  || { echo "Failed to create zip archive"; exit 1; }

# Send the archive to the FTP server
lftp -e "put \"$ARCHIVE_NAME\"; bye" -u "$FTP_USER","$FTP_PASS" "$FTP_HOST"

# Clean up
rm -rf "$TMP_DIR"

# Optionally, add logging
echo "Backup of configuration files completed on $DATE"

```