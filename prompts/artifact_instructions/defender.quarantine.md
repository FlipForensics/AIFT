Files quarantined by Windows Defender — direct evidence of detected malware.
- Every entry here is significant. This is confirmed detection, not a probabilistic indicator.
- Key fields: original file path, threat name, detection timestamp.
- Suspicious: quarantined files from startup/persistence locations (suggests malware achieved persistence before detection), repeated quarantine of the same threat (reinfection cycle), quarantine of attacker tools (mimikatz, cobalt strike, etc.).
- Cross-check: correlate quarantine timestamps with Defender EVTX for remediation success/failure, and with execution artifacts to determine if the malware ran before being caught.
- Small artifact: review all entries. Don't skip any.
