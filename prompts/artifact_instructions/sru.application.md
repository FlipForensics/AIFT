Application resource usage (CPU time, foreground time) from the SRUM database.
- Suspicious: high resource usage from unexpected or unknown processes, applications running with significant CPU time but zero foreground time (background/hidden execution).
- Context: helps identify persistent or resource-intensive processes that may indicate crypto mining, data processing, or long-running attacker tools.
- Cross-check: application names here should correlate with execution artifacts.
- Limitation: SRUM data is aggregated — it shows that something ran, not exactly what it did.
