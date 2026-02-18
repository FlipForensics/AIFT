Startup persistence. Every entry is worth reviewing — these are typically few.
- Separate HKLM (machine-wide) from HKCU (user-specific) scope.
- Suspicious: commands from user-writable paths (AppData, Temp, Public, ProgramData), script hosts (powershell, wscript, mshta, cmd /c), encoded/obfuscated arguments, LOLBins (rundll32, regsvr32, mshta).
- Expected: enterprise software updaters (Google, Adobe, Teams, OneDrive). If in doubt, flag it — false positives are cheap here.
