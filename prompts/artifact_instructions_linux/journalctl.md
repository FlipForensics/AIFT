Systemd journal — richer than syslog with structured metadata (unit names, PIDs, priority levels).
- May capture service stdout/stderr that syslog misses. Same threat indicators: authentication events, service changes, kernel messages, cron execution.
- Suspicious: journal file truncation or missing time ranges, failed service starts for security tools, kernel module loading, coredumps for exploited processes.
- Journal persistence depends on config — volatile journals (/run/log/journal/) are lost on reboot. Persistent journals live in /var/log/journal/.
- If journal has entries that syslog doesn't (or vice versa), one was likely tampered with.
