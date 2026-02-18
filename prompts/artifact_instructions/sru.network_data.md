Network usage statistics per application from the SRUM database.
- Suspicious: large data volumes from unexpected applications (potential exfiltration), network activity from known attacker tools, unusual applications making network connections.
- Key fields: application name, bytes sent/received, timestamps.
- Context: helps identify which processes were communicating and how much data moved, even if network logs aren't available.
- Limitation: SRUM aggregates data over time intervals, so precise timing of individual connections isn't available.
