Package installation and removal history — shows software changes over time.
- Suspicious: recently installed offensive tools (nmap, netcat/ncat, tcpdump, wireshark, gcc, make, gdb, strace), removed security tools (auditd, fail2ban, rkhunter, clamav), packages from non-standard repositories or PPAs, installations correlating with incident timing.
- Compiler toolchain installation (build-essential, gcc, make) on a production server is notable — may indicate kernel exploit compilation.
- Sources vary by distro: dpkg.log and apt history.log (Debian/Ubuntu), yum.log or dnf.log (RHEL/Fedora), pacman.log (Arch), zypper.log (SUSE).
- Cross-check: package installations should correlate with apt/yum/dnf commands in bash_history.
