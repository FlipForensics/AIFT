# Chunk Merge — {{artifact_name}}

This artifact's dataset was split into {{chunk_count}} chunks. Below are the per-chunk findings. Merge them into one final analysis.

## Investigation Context
{{investigation_context}}

## Per-Chunk Findings
{{per_chunk_findings}}

## Merge Rules

1. Deduplicate: if the same finding appears in multiple chunks, keep it once with the strongest evidence from any chunk.
2. Contradictions: if chunks disagree, state both positions and which has stronger evidence.
3. Drop anything that is purely informative, contextual, or a recommendation — keep only suspicious/anomalous findings.
4. Preserve all cited evidence exactly: timestamps, paths, values, row references.
5. Reorder by severity (CRITICAL → HIGH → MEDIUM → LOW), then by confidence.

## Output Format

**Findings** (skip entirely if nothing suspicious across all chunks)

- CRITICAL | HIGH confidence — What you found.
  Evidence: cited data.
  Alt: benign explanation, if any.

- HIGH | MEDIUM confidence — ...

**IOC Status** (only if investigation context mentions IOCs)

- IOC_value → Observed / Not Observed / Not Assessable. Cite evidence if observed.

**Data Gaps**

What couldn't be assessed due to chunking limitations (e.g., cross-chunk patterns that may have been missed).
