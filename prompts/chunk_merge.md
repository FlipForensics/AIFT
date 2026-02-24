# Chunk Merge — Artifact Analysis

The dataset for this artifact was too large for a single pass, so it was analyzed in {{chunk_count}} separate chunks. Below are the findings from each chunk. Merge them into one final, coherent analysis.

## Investigation Context
{{investigation_context}}

## Artifact: {{artifact_name}} ({{artifact_key}})

## Per-Chunk Findings
{{per_chunk_findings}}

## Task

Merge the above chunk analyses into one final analysis. Deduplicate repeated findings, reconcile any contradictions, and re-rank by severity then confidence.

Do not invent new findings. Only work with what is present in the chunk analyses above. If chunks contradict each other, note the conflict and state which evidence is stronger.

## Output Format

**Findings** (skip this section entirely if nothing suspicious across all chunks)

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
