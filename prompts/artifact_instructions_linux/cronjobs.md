Scheduled tasks — primary persistence mechanism on Linux.
- Suspicious: entries running scripts from /tmp, /dev/shm, or user-writable directories; entries executing curl/wget/python/bash with URLs or encoded payloads; entries owned by unexpected users; unusual schedules (every minute, @reboot).
- Locations: /var/spool/cron/crontabs/ (per-user), /etc/crontab, /etc/cron.d/, /etc/cron.{hourly,daily,weekly,monthly}/.
- @reboot entries are high-priority — they survive reboots without appearing in regular cron schedules.
- Cron execution should appear in syslog (CRON entries). Missing log entries for known cron jobs may indicate log tampering.
