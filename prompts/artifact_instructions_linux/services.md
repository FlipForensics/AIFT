Systemd service units and init scripts — key persistence and privilege artifact on Linux.
- Suspicious: unit files in /etc/systemd/system/ referencing unusual binaries, ExecStart pointing to /tmp, /dev/shm, or hidden directories, services with Restart=always that aren't standard, recently created unit files, services running as root with unusual ExecStart paths, Type=oneshot services running scripts.
- Check for: masked legitimate security services (apparmor, auditd, fail2ban), ExecStartPre/ExecStartPost running additional commands, drop-in overrides in /etc/systemd/system/*.d/ directories.
- Cross-check: service creation should correlate with systemctl commands in bash_history and file creation timestamps in filesystem artifacts.
- Expected: standard distro services are common — focus on what doesn't fit the installed package set.
