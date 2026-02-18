# Cross-Artifact Summary

Correlate findings across all artifacts below. Do not introduce evidence that isn't in the per-artifact findings.

## Investigation Context
{{investigation_context}}

## Host
{{hostname}} | {{os_version}} | Domain: {{domain}}

## Per-Artifact Findings
{{per_artifact_findings}}

## Task

Synthesize the per-artifact findings into a single incident assessment. Focus on conclusions that help the analyst decide: is this system compromised, what happened, and what to do next.

If evidence is weak or conflicting, say so. If no cross-artifact suspicious pattern exists, state that clearly — it's a valid conclusion.

## Output Format

**Executive Summary**

3-5 sentences. What happened (or likely happened) on this system? Is it compromised? How confident are you? What's the severity? This should be readable by a non-technical manager.

**Timeline**

Chronological sequence of significant events across artifacts. Each entry: timestamp, source artifact, what happened, confidence level. Only include events that matter for the incident — not routine system activity.

**IOC Status** (only if the investigation context mentions specific IOCs)

For each IOC: Observed / Not Observed / Not Assessable, with supporting artifact(s) and evidence.

**Attack Narrative** (only if evidence supports one)

Describe the likely attack sequence using phases: initial access → execution → persistence → privilege escalation → lateral movement → collection → exfiltration. Only include phases that have supporting evidence. Clearly mark any inferred steps vs. confirmed steps. If a benign explanation is equally plausible, state it.

If evidence is insufficient to construct a narrative, write: "Insufficient cross-artifact evidence to construct a reliable attack narrative" and explain what's missing.

**Gaps and Unknowns**

What questions remain unanswered? What evidence would resolve them? Note anti-forensic indicators (log clearing, timestomping, missing expected artifacts) and conflicts between artifacts.

**Recommended Next Steps**

Prioritized, actionable. Immediate containment actions first (if warranted), then investigation steps. Tie each step to a specific uncertainty or finding.
