Scheduled tasks. Primary persistence mechanism on Linux systems.
- Suspicious: entries running scripts from /tmp, /dev/shm, or user-writable directories, entries executing curl/wget/python/bash with URLs or encoded payloads, recently added entries (check file modification times), entries owned by unexpected users, entries with unusual schedules (every minute, @reboot).
- Check all cron locations: /var/spool/cron/crontabs/ (per-user), /etc/crontab, /etc/cron.d/, /etc/cron.hourly/, /etc/cron.daily/, /etc/cron.weekly/, /etc/cron.monthly/.
- Cross-check: cron execution should appear in syslog (CRON entries). Missing log entries for known cron jobs may indicate log tampering.
- @reboot entries are high-priority for persistence — they run on every boot without appearing in regular cron schedules.
