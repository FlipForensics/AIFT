Login/logout records. Linux equivalent of Windows logon events.
- Shows: user, terminal (tty/pts), source IP for remote sessions, login/logout timestamps.
- Suspicious: logins from unexpected IPs, logins at unusual hours, root logins via SSH, logins from accounts that shouldn't be interactive (www-data, nobody, service accounts), logins immediately after account creation.
- Cross-check: correlate with auth logs, bash_history, and btmp to build user activity timeline.
- Anti-forensic: wtmp is a binary file that can be tampered with using tools like utmpdump. Missing records or time gaps may indicate editing. Compare with syslog/journalctl auth entries for consistency.
