Boot/logon persistence and privilege context.
- Focus on auto-start and delayed-auto-start services.
- Suspicious: image paths under user-writable directories, service names mimicking legitimate components but pointing to odd binaries, services running as LocalSystem with unusual paths, quoted-path vulnerabilities.
- Cross-check: newly installed services should correlate with EVTX Event ID 7045.
- Expected: vendor software services are common and usually benign — look for what doesn't fit the pattern.
