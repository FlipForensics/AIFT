User accounts from /etc/passwd and /etc/shadow — Linux equivalent of the SAM artifact.
- Suspicious: UID 0 accounts besides root, accounts with no password or weak hash type (DES, MD5 instead of SHA-512), recently created accounts (check shadow change dates), accounts with interactive shells (/bin/bash, /bin/sh) that shouldn't have them (www-data, nobody, service accounts), home directories in unusual locations (/tmp, /dev/shm).
- Key fields: username, UID, GID, shell, home directory, password hash type, last password change, account expiration.
- Cross-check: new accounts should correlate with useradd commands in bash_history and auth log entries.
- Small artifact: review all entries. Focus on accounts that don't match the expected system profile.
