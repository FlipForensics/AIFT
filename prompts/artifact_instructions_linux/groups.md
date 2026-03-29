Group memberships from /etc/group — shows privilege assignments.
- Suspicious: unexpected members of sudo, wheel, adm, docker, lxd, disk, or shadow groups.
- Docker and lxd group membership effectively grants root access — flag non-admin users in these groups.
- The adm group grants log file access — membership could enable log review or tampering.
- Small artifact: review all privileged group memberships completely.
