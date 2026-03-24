SSH public keys that grant passwordless access. Critical persistence mechanism.
- Suspicious: keys in unexpected user accounts (especially root, service accounts), recently added keys (correlate with file timestamps from filesystem artifacts), keys with forced command restrictions that look like backdoors (command="..." prefix), multiple keys for single accounts that don't match known administrators, keys with unusual comment fields.
- Check: ~/.ssh/authorized_keys and ~/.ssh/authorized_keys2 for all users, plus /etc/ssh/sshd_config for AuthorizedKeysFile overrides pointing to non-standard locations.
- Cross-check: key additions should correlate with SSH or SCP activity in auth logs, and echo/cat commands in bash_history writing to authorized_keys files.
- An attacker adding their key is one of the most common Linux persistence techniques — always review thoroughly.
