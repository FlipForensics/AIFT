Last login timestamp and source for each user account — quick-reference artifact.
- Quick checks: accounts with recent logins that shouldn't be active (service accounts, disabled users), system accounts (UID < 1000) with login records, accounts that have never logged in but were recently created.
- Only stores the most recent login per user — no history. Cross-check against wtmp for full login records.
- Discrepancies between lastlog and wtmp may indicate tampering with one or both.
- Small artifact: review all entries.
