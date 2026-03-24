Systemd service units and init scripts. Key persistence and privilege artifact.
- Suspicious: unit files in /etc/systemd/system/ referencing unusual binaries, ExecStart pointing to /tmp, /dev/shm, or hidden directories, services with Restart=always that aren't standard system services, recently created unit files, services running as root with unusual ExecStart paths, services with Type=oneshot that run scripts.
- Check for: masked legitimate security services (apparmor, auditd, fail2ban), services with ExecStartPre/ExecStartPost running additional commands, drop-in overrides in /etc/systemd/system/*.d/ directories.
- Cross-check: service creation should correlate with systemctl commands in bash_history and file creation timestamps in filesystem artifacts.
- Expected: standard distro services are common — look for what doesn't fit the installed package set.
