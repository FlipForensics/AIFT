Direct record of commands typed by users. Highest-value artifact on Linux systems.
- Suspicious: curl/wget download commands, base64 encoding/decoding, reverse shells (bash -i, /dev/tcp), compiler invocations (gcc, make) for kernel exploits, credential access (cat /etc/shadow, mimipenguin), reconnaissance (id, whoami, uname -a, cat /etc/passwd, ss -tlnp, ip a), persistence installation (crontab -e, systemctl enable), log tampering (truncate, shred, rm on /var/log).
- No timestamps in bash_history. Sequence matters but timing must come from other artifacts.
- Sparse or empty history for active accounts may indicate clearing (history -c, HISTFILE=/dev/null, unset HISTFILE).
- Look for multi-stage attack patterns: recon commands followed by exploitation, then persistence.
- Commands with pipes to /dev/null or stderr redirection may indicate attempts to suppress output.
