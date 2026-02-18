Supplementary execution evidence — records executable descriptions from PE metadata when programs run.
- Lower-confidence artifact on its own. Use primarily to corroborate findings from prefetch, amcache, and shimcache.
- Suspicious: uncommon executables in user-writable directories, entries suggesting renamed binaries (description doesn't match filename), known attacker tool names.
- Value: can reveal executables that ran but were later deleted, since the MUIcache entry persists in the registry.
- Limitation: no timestamps. Only shows that something ran at some point. Always pair with other artifacts for timing.
