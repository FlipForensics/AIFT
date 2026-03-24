SSH host keys for systems this machine has connected to. Shows lateral movement paths outward.
- Suspicious: internal hosts that shouldn't be SSH targets from this system, external IPs or hostnames, large number of known hosts on a system that shouldn't be doing SSH (web servers, database servers), recently added entries (correlate with file timestamps).
- Hashed known_hosts (HashKnownHosts=yes) obscure the hostnames — presence of hashed entries limits analysis but the count and file modification time are still useful.
- Check both per-user (~/.ssh/known_hosts) and system-wide (/etc/ssh/ssh_known_hosts).
- Cross-check: SSH connections should correlate with outbound connection entries in bash_history (ssh commands) and auth logs on the destination systems.
