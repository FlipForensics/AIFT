# Artifact Analysis

## Investigation Context
{{investigation_context}}

## Artifact: {{artifact_name}}
{{artifact_description}}

## What To Look For In This Artifact
{{artifact_guidance}}

## Data
Records: {{total_records}} | Time range: {{time_range_start}} to {{time_range_end}}

### Statistics
{{statistics}}

### Full Data (CSV)
```
{{data_csv}}
```

## Task

Analyze this data for evidence of compromise in the context of the investigation above.

Focus on what matters most: findings that confirm, scope, or help respond to a potential incident. Skip routine observations unless they provide context for a suspicious finding.

If IOCs or specific targets are mentioned in the investigation context, explicitly state whether each is Observed, Not Observed, or Not Assessable in this data.

If nothing suspicious exists, say so in one sentence and move on to data limitations.

## Output Format

**Findings** (skip this section entirely if nothing suspicious)

For each finding, use this format:
- [SEVERITY: CRITICAL|HIGH|MEDIUM|LOW] [CONFIDENCE: HIGH|MEDIUM|LOW] What you found.
  - Evidence: timestamp, value, and row reference from the data.
  - Why it matters: one sentence on incident impact or risk.
  - Alternative explanation: most likely benign reason for this, if any.
  - Verify: one specific follow-up action.

Order by severity, then confidence. Do not pad with low-value observations.

**IOC Status** (only if the investigation context mentions specific IOCs)

- IOC → Observed / Not Observed / Not Assessable. Evidence if observed.

**Data Gaps**

What can't be determined from this artifact and why. Include: missing time ranges, absent fields, signs of tampering or log clearing, and what other artifacts would help.
