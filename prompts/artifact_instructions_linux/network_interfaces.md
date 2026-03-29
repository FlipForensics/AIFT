Network interface configuration — context artifact for understanding the system's network position.
- Shows: interface names, IP addresses, subnet masks, gateways, DNS servers, VLAN configurations.
- Useful for: determining reachable networks, identifying multi-homed systems, understanding blast radius of a compromise.
- Suspicious: unexpected interfaces (tun/tap for VPN tunnels, docker/veth for containers that shouldn't exist), promiscuous mode enabled (potential sniffing), IP addresses outside expected ranges.
- Primarily a context artifact — use it to inform analysis of other artifacts rather than as a standalone finding source.
