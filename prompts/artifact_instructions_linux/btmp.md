Failed login attempts. Linux equivalent of Windows Event ID 4625.
- Suspicious patterns: brute force (high volume against one account), password spraying (low volume across many accounts), attempts against disabled or system accounts (root, admin, service accounts).
- Source IPs are key IOCs — extract and correlate with successful logins in wtmp.
- Successful login after many failures may indicate compromised credentials.
- High volume is normal for internet-facing SSH — focus on attempts against real local accounts rather than dictionary usernames.
- Cross-check: correlate timestamps with wtmp to find brute-force-then-success sequences.
