```bash
#!/bin/bash

# Check for zip command
command -v zip >/dev/null 2>&1 || { echo "zip command is required but it's not installed. Aborting." >&2; exit 1; }


# Define variables
DATE=$(date +'%Y.%m.%d')
ARCHIVE_NAME="/var/backups/server/${DATE}_mysql.zip"


# Load FTP credentials
FTP_HOST=$(grep 'host=' /root/.ftp_credentials | cut -d '=' -f2 | xargs)
FTP_USER=$(grep 'user=' /root/.ftp_credentials | cut -d '=' -f2 | xargs)
FTP_PASS=$(grep 'password=' /root/.ftp_credentials | cut -d '=' -f2 | xargs)


echo "FTP_HOST: $FTP_HOST"
echo "FTP_USER: $FTP_USER"
echo "FTP_PASS: $FTP_PASS"

# Create a temporary directory
TMP_DIR=$(mktemp -d)

databases=$(mysql -Bse "SHOW DATABASES;" | grep -Ev "(information_schema|performance_schema|mysql|sys)")

# Export each database
for db in $databases; do
    mysqldump "$db" > "$TMP_DIR/$db.sql"
done

# Export users
mysql -e "SELECT User, Host FROM mysql.user" > "$TMP_DIR/mysql_users.txt"

# Change to the temporary directory to ensure zip archives contents directly
cd "$TMP_DIR" || exit

# Create the archive
zip -r "$ARCHIVE_NAME" ./*  || { echo "Failed to create zip archive"; exit 1; }

# Send the archive to the FTP server
lftp -e "put \"$ARCHIVE_NAME\"; bye" -u "$FTP_USER","$FTP_PASS" "$FTP_HOST"

# Clean up
rm -rf "$TMP_DIR"

# Optionally, add logging
echo "Backup of MariaDB databases completed on $DATE"
```