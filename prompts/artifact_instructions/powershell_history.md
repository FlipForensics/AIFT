Direct record of PowerShell commands typed by users. High-value tradecraft evidence.
- Suspicious: encoded commands (-enc / -EncodedCommand), download cradles (IWR, Invoke-WebRequest, Net.WebClient), execution policy bypasses, AMSI bypasses, credential access cmdlets, discovery commands (whoami, net user, Get-ADUser, nltest), lateral movement (Enter-PSSession, Invoke-Command), file staging and archiving.
- Anti-forensic: sparse or truncated history may indicate clearing (Clear-History, deletion of ConsoleHost_history.txt).
- No timestamps: PSReadLine history is a plain text file without timestamps. Sequence matters but timing must come from other artifacts.
- This is often the highest-signal artifact when present. Treat every line as potentially significant.
