Zsh shell command history with timestamps. Higher value than bash_history for timeline construction.
- Format: each entry has `: epoch:duration;command` — use the epoch timestamp for timeline correlation.
- Same threat indicators as bash_history: curl/wget downloads, base64, reverse shells, credential access, recon commands, persistence installation, log tampering.
- Timestamps allow direct correlation with other timed artifacts (wtmp, syslog, journalctl).
- Zsh extended history may record multi-line commands that bash_history splits or truncates.
- Sparse or empty history for active accounts may indicate clearing or HISTFILE manipulation.
