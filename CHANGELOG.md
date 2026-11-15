# Changelog

Development moved to https://code.bashclub.org/bashclub/checkmk-opnsense-agent with 1.2.17. Issue and PR numbers
(#n) refer to the former GitHub repository. Changes before 1.2.17 are only in the git history.

After an update, run a service discovery in Checkmk: several checks report new services or no longer report
services that were wrong before.

## 1.2.19 – testing
- **Disks** (SMART and wearout like "PVE Disks" of cmk-push-agent, needs plugin os-smart): `Disks`,
  `Disk <serial> SMART` (self-assessment, attributes below threshold, last self-test, rising counters, NVMe spare) and
  `Disk <serial> Wearout` (remaining life of SSD/NVMe with forecast). Aborted self-tests are no failure.
- Config file: a known option without colon (`skipservice ntpd`) is read, with a note in the system log (#2).

## 1.2.18 – 2026-11-15

### New
- **Certificates** (#66): one service per certificate (`Certificate: <description>`) and own CA (`CA: <description>`)
  in System > Trust with metric `expiredays`, WARN below 30 days, CRIT below 14. Left out: CAs imported without
  private key (e.g. intermediates of the ACME client), ACME certificates (service `ACME Cert`), certificates expired
  for more than 30 days. New option `skipcert` (description, CN or refid).
- **Caddy** (plugin os-caddy): one service per reverse proxy domain (`Caddy Domain: <domain>`): upstreams reachable
  (TCP), certificate managed by Caddy renewed in time.
- **IPsec connections** (swanctl, OPNsense 23.1+) besides the legacy tunnels (PRs #37, #69, #72): all enabled
  children must be up, missing ones are named (WARN).
- **Kea DHCPv4** (#75, PR #81 by Johannes Braun) and **Dnsmasq DHCP**: pools and active leases in the DHCP section,
  together with ISC DHCP.
- **NetBird** (PR #81 by Johannes Braun): services for the daemon and each peer, only when NetBird is enabled; idle
  peers are OK, option `netbird_idle` (ok, warn, crit).
- **CARP** (#76): OpenVPN and IPsec tunnels bound to a CARP VIP are OK on the node where the VIP is not MASTER
  ("CARP BACKUP …, tunnel only runs on the master").
- **lagg interfaces** and their members are monitored (PRs #59, #60 by Marius Rieder).
- **Firmware**: updates of plugins/packages without a new OPNsense version are reported (WARN, metric
  `package_updates`) (#84).
- Option **`skipservice`**: OPNsense services that may be stopped on purpose (idea from PR #70 by Marc Risse).
- **`onlyfrom`** accepts networks (CIDR).
- The running agent applies changes of `onlyfrom`, `encrypt`, `skipcheck`, `skipservice`, `skipcert`,
  `netbird_idle` and `tenants` in `/usr/local/etc/checkmk.conf` without restart; lines it cannot read are logged.
- Handbook in `docs/handbuch`, published on https://docs.bashclub.org/s/checkmk-opnsense-agent.

### Changed
- **OpenVPN** reworked (#82, #80, #67, #41, PR #71 by Stefan Meinecke): instances and legacy servers/clients side by
  side; client instances are connections; an unreachable server reports "Server down" instead of stopping the check;
  OpenVPN 2.7 addresses (`udp4:…`).
- **WireGuard** (#52, PR #85 by HannesMC): roadwarrior peers without endpoint are OK when disconnected, disabled
  peers and peers of disabled instances are not reported; the text starts with `online`/`offline`.
- **CARP** service shows `advskew` and what it expects when it is WARN (#48).
- Disabled VPN tunnels (WireGuard, OpenVPN, IPsec) are not reported (#39).
- SMART: the help recommends `smart_posix` from Checkmk, the checkmk-smart MKP as alternative (#83).
- Service names without quotes: a `'` in a description (e.g. "Let's Encrypt") made Checkmk reject the line.

### Fixed
- `onlyfrom` rejected every IPv4 client since 1.2.11 (dual-stack socket); only IPv4/IPv6 addresses and networks are
  accepted, without a valid entry nobody (fail closed); rejected clients are logged.
- `tenants` without password stopped the agent.
- IPsec: phase 1 without description stopped the check (#34).
- `ps`: processes with state `S<`/`I<` and users with `-` were missing (#86).
- Certificates: config.xml without `<cert>` stopped the checks using certificates.
- Empty `<interfaces/>` stopped the interface and gateway checks.
- Spool files: the max age prefix (`600_name`) works.
- Tasks: service names in double quotes, `CMK Tasks` in its own section, blocklist by hostname.
- `skipcheck: a, b` with spaces.
- NetBird installed but switched off: no CRIT and no 20 s delay of every agent query.

## 1.2.17 – 2026-11-15
- A missing or broken firmware changelog (`/usr/local/opnsense/changelog/index.json`, OPNsense 26.7.9,
  opnsense/core#11198) no longer stops the agent (#87, #88, PR #74).
- Local check `Checkmk Agent Update`: once a day, WARN when a new release (or testing version) is available.
- `--update` (release) and `--update testing` load from code.bashclub.org.
