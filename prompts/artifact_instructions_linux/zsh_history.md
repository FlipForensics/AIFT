Zsh shell history with timestamps — higher value than bash_history for timeline construction.
- Format: `: epoch:duration;command` — use the epoch timestamp for direct correlation with other timed artifacts (wtmp, syslog, journalctl).
- Same threat indicators as bash_history: curl/wget downloads, base64, reverse shells, credential access, recon commands, persistence installation, log tampering.
- Zsh extended history may record multi-line commands that bash_history splits or truncates.
- Sparse or empty history for active accounts may indicate clearing or HISTFILE manipulation.
