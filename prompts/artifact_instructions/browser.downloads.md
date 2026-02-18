Files downloaded through web browsers with source URL and local save path.
- Suspicious: downloaded executables, scripts, archives, disk images, office documents with macros — especially from unknown or suspicious URLs.
- High-value cross-check: a downloaded file that also appears in execution artifacts (prefetch, amcache) confirms the payload was run.
- Flag: repeated downloads of similarly named files (retry behavior), downloads from raw IP URLs, filename/extension mismatches.
- Key fields: source URL, local path, download timestamp.
