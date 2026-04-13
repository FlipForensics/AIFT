# Cross-Image Correlation Analysis

You are correlating findings across multiple disk images from the same investigation. Per-image summaries are provided below — do NOT fabricate evidence beyond what is stated in them.

## Investigation Context
{{investigation_context}}

## Systems Under Analysis
{{image_metadata_table}}

## Per-Image Summaries
{{per_image_summaries}}

## Task

Correlate the per-image findings into a unified multi-system assessment. If no cross-system activity is apparent, state that clearly — single-system compromise with no lateral movement is a valid and useful conclusion.

## Output

**Cross-System Executive Summary**

3–5 sentences for a non-technical reader. What happened across these systems? Multi-system incident or isolated to one host? Overall severity and confidence.

**Cross-System Connections** (skip if none found)

Specific links between systems: shared accounts or credentials, network connections (RDP, SMB, WinRM, SSH), lateral movement paths, shared executables or tools, shared external IPs or domains. For each: which systems, what evidence, confidence level.

**Multi-System Timeline**

Chronological sequence of significant events across all systems. Each entry: timestamp, source system, source artifact, what happened. Order to show the flow of activity between hosts. Highlight first appearance of IOCs or attacker activity on each new system.

**Patient Zero** (only if evidence supports an assessment)

Which system was likely compromised first, and what evidence supports it. If insufficient evidence, state that in one sentence and move on.

**Shared IOCs** (skip if none found)

IOCs appearing on more than one system: value, type, which systems, and whether it appeared before or after suspected compromise on each.

**Scope Assessment**

Which systems show signs of compromise and which don't. This defines the blast radius.

**Gaps and Recommendations**

What cross-system questions remain unanswered? What additional evidence would clarify the picture? Prioritized next steps.
