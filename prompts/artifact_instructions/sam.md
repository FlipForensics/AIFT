Local user accounts from the SAM registry hive.
- Suspicious: recently created accounts (especially near the incident window), accounts added to the Administrators group, accounts with names mimicking system accounts, re-enabled previously disabled accounts, password changes on accounts that shouldn't change.
- Key fields: account name, creation date, last password change, group memberships, account flags (enabled/disabled).
- Cross-check: account creation/modification should correlate with EVTX Event IDs 4720, 4722, 4724, 4732.
- Small artifact: SAM typically has few entries. Review all of them, not just flagged ones.
