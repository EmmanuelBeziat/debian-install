```bash
#!/bin/bash

# Check for zip command
command -v zip >/dev/null 2>&1 || { echo "zip command is required but it's not installed. Aborting." >&2; exit 1; }

# Define variables
DATE=$(date +'%Y.%m.%d')
ARCHIVE_NAME="/var/backups/server/${DATE}_mails.zip"

# Load FTP credentials
FTP_HOST=$(grep '^host=' /root/.ftp_credentials | cut -d '=' -f2- | tr -d '\r' | xargs)
FTP_USER=$(grep '^user=' /root/.ftp_credentials | cut -d '=' -f2- | tr -d '\r' | xargs)
FTP_PASS=$(grep '^password=' /root/.ftp_credentials | cut -d '=' -f2- | tr -d '\r' | xargs)

# Discover every mailbox dynamically instead of a hardcoded list, so newly
# added domains/mailboxes (via add-mail-domain / add-mailbox) are picked up
# automatically instead of silently going unbacked-up.
MAILS=()
while IFS= read -r -d '' mailbox; do
    MAILS+=("$mailbox")
done < <(find /var/mail/vhosts -mindepth 2 -maxdepth 2 -type d -print0)

# Maximum file size parameter (e.g., 1024m for 1024 MB); leave empty for no limit
MAX_SIZE="${1:-}"

# Create a temporary directory for organized backup structure
TMP_DIR=$(mktemp -d)

# Build rsync options based on MAX_SIZE
RSYNC_OPTS=("--relative" "-av")
[ -n "$MAX_SIZE" ] && RSYNC_OPTS+=("--max-size=$MAX_SIZE")

# Copy files while preserving directory structure in temporary directory
for MAILS_FILES in "${MAILS[@]}"; do
    rsync "${RSYNC_OPTS[@]}" "$MAILS_FILES" "$TMP_DIR"
done

# Change to the temporary directory to ensure zip archives contents directly
cd "$TMP_DIR" || exit

# Replace any archive from an earlier run today (zip -r would merge into it)
rm -f "$ARCHIVE_NAME"

# Create the archive from the contents of TMP_DIR
zip -r "$ARCHIVE_NAME" ./*  || { echo "Failed to create zip archive"; exit 1; }

# Send the archive to the FTP server, encrypted: Dedibackup is plain FTP.
# The local zip stays in clear (backup-offsite.sh encrypts it with rclone crypt).
# Password via env var, not argv, so it never shows up in `ps`
PASSPHRASE_FILE=/root/.backup-passphrase
if ! gpg --batch --yes --quiet --symmetric --cipher-algo AES256 \
        --passphrase-file "$PASSPHRASE_FILE" -o "$ARCHIVE_NAME.gpg" "$ARCHIVE_NAME"; then
    echo "ERROR: encryption of $ARCHIVE_NAME failed on $DATE (missing $PASSPHRASE_FILE?), not uploaded" >&2
    FTP_FAILED=1
elif ! LFTP_PASSWORD="$FTP_PASS" lftp -e "set net:max-retries 3; set net:timeout 30; put \"$ARCHIVE_NAME.gpg\"; bye" -u "$FTP_USER" --env-password "$FTP_HOST"; then
    echo "ERROR: FTP upload of $ARCHIVE_NAME.gpg failed on $DATE" >&2
    FTP_FAILED=1
fi
rm -f "$ARCHIVE_NAME.gpg"

# Clean up
rm -rf "$TMP_DIR"

# Optionally, add logging
echo "Backup of mails completed on $DATE"

exit "${FTP_FAILED:-0}"
```
