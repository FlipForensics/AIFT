Primary system log. Broadest coverage of system events on Linux.
- High-signal entries to prioritize: authentication events (sshd, sudo, su, login), service start/stop, kernel messages (especially module loading via modprobe/insmod), cron execution, package manager activity, error patterns, and OOM kills.
- Filter by the investigation timeframe first — syslog can be very high volume.
- Suspicious: gaps in timestamps (log deletion/rotation tampering), sshd accepted/failed password entries, sudo command executions, unknown or unexpected service names, kernel module loading for non-standard modules.
- Cross-check: syslog auth entries should be consistent with wtmp/btmp records. Discrepancies indicate tampering.
- Volume warning: syslog can have millions of lines. Focus on the incident time window and high-signal facility/program combinations.
