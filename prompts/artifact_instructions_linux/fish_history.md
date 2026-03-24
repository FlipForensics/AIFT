Fish shell command history with timestamps. Same threat indicators as bash_history.
- Fish stores history in its own format with `- cmd:` and `when:` fields — timestamps are Unix epochs.
- Same suspicious patterns: downloads, reverse shells, credential access, recon, persistence, log tampering.
- Fish is uncommon on servers. Its presence on a production system may itself be notable — check if it was recently installed via package manager artifacts.
- Fish history is stored per-user in ~/.local/share/fish/fish_history.
