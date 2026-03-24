Package installation and removal history. Shows software changes over time.
- Suspicious: recently installed offensive tools (nmap, netcat/ncat, tcpdump, wireshark, gcc, make, gdb, strace, python3-pip), removed security tools (auditd, fail2ban, rkhunter, clamav), packages from non-standard repositories or PPAs, package installations that correlate with incident timing.
- Sources vary by distro: dpkg.log and apt history.log (Debian/Ubuntu), yum.log or dnf.log (RHEL/Fedora), pacman.log (Arch), zypper.log (SUSE).
- Cross-check: package installations should correlate with apt/yum/dnf commands in bash_history.
- Compiler toolchain installation (build-essential, gcc, make) on a production server is notable — may indicate kernel exploit compilation.
