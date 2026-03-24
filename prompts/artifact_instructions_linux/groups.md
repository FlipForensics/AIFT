Group memberships from /etc/group. Shows privilege assignments.
- Suspicious: unexpected members of privileged groups (sudo, wheel, adm, docker, lxd, disk, shadow), recently modified groups, custom groups with unusual memberships.
- Docker and lxd group membership effectively grants root access — flag non-admin users in these groups.
- The adm group grants access to log files — membership could enable log review or tampering.
- Cross-check: group changes should correlate with usermod/gpasswd commands in bash_history and auth logs.
- Small artifact: review all privileged group memberships.
