# check-opnsense

## How to install

SSH into your OPNsense:
```
fetch -o /usr/local/etc/rc.syshook.d/start/99-checkmk_agent https://github.com/bashclub/check-opnsense/raw/main/opnsense_checkmk_agent.py
chmod +x /usr/local/etc/rc.syshook.d/start/99-checkmk_agent
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent
```

Ensure you create a packet filter rule to allow connections from your checkmk server to the firewall on port 6556.

## NetBird monitoring

If the `netbird` CLI is installed, the agent adds local checks for NetBird automatically:

- `NetBird` summary with daemon, management, signal and peer counts
- `NetBird Peer: <name>` for each peer from `netbird status --json`

Peer checks report the NetBird connection state, connection type, latency, last WireGuard handshake age when available, and traffic counters. On kernel WireGuard setups the agent also correlates peers with `wg show all dump` by public key for handshake and byte counters. Userspace NetBird setups still get connection state from the NetBird daemon.

To disable these checks, add `netbird` to `skipcheck` in `/usr/local/etc/checkmk.conf`.

## Kea DHCP monitoring

On newer OPNsense versions, where ISC DHCP has been replaced by Kea, the agent reads `/usr/local/etc/kea/kea-dhcp4.conf` and `/var/db/kea/kea-leases4.csv*` and exposes the DHCP pools and active leases through the existing Checkmk DHCP section. If ISC DHCP and Kea DHCP are both present, their pools and leases are merged into a single section.
