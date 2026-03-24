Sudo configuration defining privilege escalation rules.
- Suspicious: NOPASSWD entries (allow sudo without password), overly broad command allowances (ALL=(ALL) ALL for non-admin users), entries for unexpected users or groups, entries allowing specific dangerous commands (bash, su, cp, chmod, chown), entries with !authenticate.
- Check both /etc/sudoers and /etc/sudoers.d/ drop-in files.
- Recently modified sudoers files are high-priority — correlate modification timestamps with other activity.
- Attackers commonly add NOPASSWD entries for persistence or lateral movement.
- Cross-check: sudoers modifications should correlate with visudo usage in bash_history or file modification timestamps.
