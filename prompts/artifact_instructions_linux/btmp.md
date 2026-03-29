Failed login attempts — Linux equivalent of Windows Event ID 4625.
- Patterns: brute force (high volume against one account), password spraying (low volume across many accounts), attempts against disabled or system accounts.
- Source IPs are key IOCs. A successful login (in wtmp) after many failures here indicates compromised credentials.
- High volume is normal for internet-facing SSH — focus on attempts against real local accounts rather than dictionary usernames.
