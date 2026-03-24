Network interface configuration. Context artifact for understanding the system's network position.
- Shows: interface names, IP addresses, subnet masks, gateways, DNS servers, VLAN configurations.
- Useful for: determining what networks the system could reach, identifying multi-homed systems (multiple interfaces/IPs), understanding the blast radius of a compromise.
- Suspicious: unexpected interfaces (tun/tap for VPN tunnels, docker/veth for containers that shouldn't exist), promiscuous mode enabled (potential sniffing), IP addresses outside expected ranges.
- Sources: /etc/network/interfaces, /etc/netplan/*.yaml, NetworkManager configs, ip addr output.
- This is primarily a context artifact — use it to inform analysis of other artifacts rather than as a standalone finding source.
