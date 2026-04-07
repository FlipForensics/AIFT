# Cross-Image Correlation Analysis

You are performing a cross-system forensic correlation across multiple disk images from the same investigation. Each image represents a different system (workstation, server, domain controller, etc.). Per-image summaries are provided below — do NOT fabricate evidence beyond what is stated in them.

## Investigation Context
{{investigation_context}}

## Systems Under Analysis

{{image_metadata_table}}

## Per-Image Summaries

{{per_image_summaries}}

## Task

Correlate the per-image findings into a unified multi-system incident assessment. Focus on connections, movement, and shared indicators across systems.

If evidence across systems is weak or no cross-system activity is apparent, state that clearly — single-system compromise with no lateral movement is a valid conclusion.

## Output Format

**Cross-System Executive Summary**

3-5 sentences. What happened across these systems? Is this a multi-system incident or isolated to one host? How confident are you? What is the overall severity? This should be readable by a non-technical manager.

**Cross-System Connections**

Identify specific connections between systems:
- Shared user accounts or credentials observed on multiple systems
- Network connections between systems (RDP, SMB, WinRM, SSH, etc.)
- Lateral movement paths (how the attacker moved between systems)
- Shared executables or tools appearing on multiple systems
- Shared IPs or domains contacted by multiple systems

For each connection: which systems are involved, what evidence supports it, and confidence level.

If no cross-system connections are found, state: "No cross-system connections identified in the available evidence."

**Multi-System Timeline**

Chronological sequence of significant events across ALL systems. Each entry: timestamp, source system (image label), source artifact, what happened, confidence level.

Order events to show the flow of activity between hosts. Highlight the first appearance of IOCs or attacker activity on each system.

**Patient Zero Assessment**

Which system was likely compromised first? What evidence supports this? Rate confidence (High/Medium/Low). If evidence is insufficient to determine patient zero, state that clearly.

**Shared IOCs**

IOCs (hashes, IPs, domains, filenames, accounts) that appear on more than one system:
- IOC value, type, and which systems it was observed on
- Whether it appeared before or after the suspected compromise on each system

If no shared IOCs are found, state: "No shared IOCs identified across systems."

**Uncompromised Systems**

List any systems that show no signs of compromise. This is useful for incident scoping — it helps determine the blast radius.

**Overall Incident Confidence**

Rate the overall confidence in the multi-system assessment:
- **High**: Clear evidence of cross-system activity with corroborating artifacts
- **Medium**: Some indicators of cross-system activity but gaps in evidence
- **Low**: Limited evidence; cross-system conclusions are largely inferred

**Gaps and Recommendations**

What cross-system questions remain unanswered? What additional evidence or analysis would help? Prioritized next steps for the investigation, focusing on actions that would clarify the cross-system picture.
