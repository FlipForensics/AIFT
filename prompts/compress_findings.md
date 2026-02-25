Compress the per-artifact findings below into shorter summaries for use in cross-artifact correlation. One bullet per artifact.

Preserve: every suspicious finding, anomaly, IOC match, cited timestamp, path, IP, account, and confidence rating. These are non-negotiable — if it was flagged as suspicious, it stays.

Drop: routine observations, "nothing found" padding, context-only descriptions of what the artifact contains, recommendations, and alternative explanations.

Target: each artifact summary should be 2–4 sentences. If an artifact had no suspicious findings, compress to: "- artifact_name: No suspicious findings."

Output format — no preamble, just the list:

- artifact_name: compressed findings with key evidence preserved.
- artifact_name: compressed findings...
- artifact_name: No suspicious findings.

## Findings to Compress
{{per_artifact_findings}}
