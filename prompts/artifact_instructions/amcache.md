Program inventory with execution relevance and SHA-1 hashes.
- Suspicious: newly observed executables near the incident window, uncommon install paths, unknown publishers, product name mismatches, executables without expected publisher metadata.
- High value: SHA-1 hashes can be cross-referenced with threat intel (note this for the analyst, but don't fabricate lookups).
- Cross-check: correlate with shimcache and prefetch for execution confirmation.
- Expected: normal software installs and updates are common — focus on what appeared recently or doesn't belong.
