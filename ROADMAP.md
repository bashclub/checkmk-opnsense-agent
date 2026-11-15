# Roadmap

Planned features and larger reworks. Bugs are tracked as issues on
https://code.bashclub.org/bashclub/checkmk-opnsense-agent/issues; known bugs with workarounds are listed in the
handbook (`docs/handbuch/03-fehlerbehebung/02-bekannte-probleme.md`).

## Feature requests
- **Caddy** (plugin `os-caddy`): service running, reverse proxy domains/handlers, certificates.
- **Dnsmasq DHCP:** pools and leases (default DHCP server of new OPNsense installations).
- **Certificate monitoring:** expiry of all certificates in the trust store, not only OpenVPN and ACME (GitHub #66).
- **SMART:** test `smart_posix` from Checkmk on real hardware (documented after user feedback, GitHub #83).
