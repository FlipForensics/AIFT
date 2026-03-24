Systemd journal. Richer than syslog with structured metadata including unit names, PIDs, and priority levels.
- Same threat indicators as syslog: authentication events, service changes, kernel messages, cron execution.
- Advantages over syslog: structured fields allow better filtering by unit, priority, or time range. May capture output that syslog misses (stdout/stderr of services).
- Suspicious: journal file truncation or missing time ranges, failed service starts for security tools, kernel module loading, coredumps for exploited processes.
- Cross-check: journal entries should be consistent with syslog. If journal has entries that syslog doesn't (or vice versa), investigate which was tampered with.
- Journal persistence depends on configuration — volatile journals are lost on reboot. Check /var/log/journal/ vs /run/log/journal/.
