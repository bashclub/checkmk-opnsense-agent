# Roadmap

Planned features and larger reworks. Bugs are tracked as issues on
https://code.bashclub.org/bashclub/checkmk-opnsense-agent/issues; known bugs with workarounds are listed in the
handbook (`docs/handbuch/03-fehlerbehebung/02-bekannte-probleme.md`).

## Reworks
- **OpenVPN:** rework of the check for instances and legacy servers (GitHub #82, #80, #71, #67, #41; PR #71), with
  "Server down" instead of a failing check.
- **IPsec connections (swanctl, OPNsense 23.1+):** besides the legacy tunnels (GitHub PRs #69, #72, #37; #34).

## Feature requests
- **Caddy** (plugin `os-caddy`): service running, reverse proxy domains/handlers, certificates.
- **Kea DHCP:** pools and leases (GitHub #75, PR #81).
- **NetBird** (GitHub PR #81).
- **Consider the CARP state:** no CRIT for tunnels on the backup node (GitHub #76; #48).
- **Certificate monitoring:** expiry of all certificates in the trust store, not only OpenVPN and ACME (GitHub #66).
- **Firmware:** report package and plugin updates without a new OPNsense version (GitHub #84).
- **`onlyfrom` with networks (CIDR).**
- **SMART:** test and document `smart_posix` from Checkmk as alternative to the checkmk-smart MKP (GitHub #83).

Disabled VPN connections (GitHub #39) are covered for WireGuard since 1.2.18; OpenVPN and IPsec follow with their
reworks.
