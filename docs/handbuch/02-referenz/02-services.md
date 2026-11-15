---
title: Services und Zustände
audience: Anwender, Admin
outline:
---
Der Agent liefert zwei Arten von Daten:
- **Lokale Checks:** fertige Services mit Zustand, die der Agent selbst bewertet. Sie beschreiben die OPNsense
  (Firmware, VPN, Gateways …).
- **Abschnitte** (Sections): Rohdaten, die Checkmk mit seinen eigenen Check-Plugins auswertet, wie beim Linux-Agent
  (CPU, Speicher, Interfaces …). Schwellwerte dafür stellt man in Checkmk ein.

Jeder Check lässt sich mit `skipcheck` abschalten; der Name steht in der ersten Spalte
([Konfiguration](01-konfiguration.md)). Ein Check, der nichts zu prüfen hat (z. B. kein WireGuard eingerichtet),
liefert keinen Service.

## Lokale Checks
| `skipcheck` | Service | OK | WARN | CRIT |
|---|---|---|---|---|
| `firmware` | `Firmware` | aktuelle Version | Update verfügbar (auch Major-Upgrade) | – |
| `business` | `Business Licence` | Lizenz läuft länger als 60 Tage | unter 60 Tagen | unter 30 Tagen |
| `agentupdate` | `Checkmk Agent Update` | Agent aktuell oder keine Prüfung möglich | neue Version ([Updates](../01-einrichtung/03-updates.md)) | – |
| `services` | `Services` | alle Dienste der OPNsense laufen | – | ein Dienst läuft nicht |
| `pkgaudit` | `Audit` | `pkg audit` findet nichts | Pakete mit bekannten Sicherheitslücken | – |
| `carpstatus` | `CARP: <Interface>@<VHID>` | erwarteter Zustand | anderer Zustand | – |
| `gateway` | `Gateway <Name>` | ohne Verlust, Laufzeit bis 100 ms | Verlust oder Laufzeit über 100 ms | Verlust über 90 % oder keine Daten |
| `openvpn` | `OpenVPN Server: <Name>`, `OpenVPN Client: <Name>`, `OpenVPN Connection: <Name>` | läuft bzw. verbunden | wartet auf Verbindung; Zertifikat läuft in unter 61 Tagen ab | Server down, nicht verbunden; Zertifikat in unter 31 Tagen |
| `ipsec` | `IPsec Tunnel: <Name>` | Tunnel aufgebaut mit Phase 2 bzw. allen Children | ab 1.2.18: nur ein Teil der Children einer Verbindung aufgebaut | nicht verbunden, IPsec läuft nicht |
| `wireguard` | `WireGuard Client: <Name>` | verbunden; Roadwarrior auch getrennt | – | Site-to-Site ohne Handshake seit 5 min; Instanz läuft nicht |
| `netbird` | `NetBird`, `NetBird Peer: <Name>` | ab 1.2.18: Daemon, Management und Signal verbunden; Peer verbunden | Management oder Signal getrennt; Peer `Connecting`/`Idle` oder Handshake älter als 5 min | Daemon nicht verbunden (z. B. `NeedsLogin`), keine Daten; Peer getrennt |
| `unbound` | `Unbound DNS` | läuft, mit Anfragen und Cache-Treffern | – | läuft nicht |
| `acmeclient` | `ACME Cert: <Name>` | Zertifikat erneuert | ausstehend | Fehler, Ablauf in unter 10 Tagen |
| `nginx` | `Nginx Uptime`, `Nginx Location: <Name>` | läuft, Upstreams erreichbar | Upstream teilweise erreichbar, keine Daten | nginx läuft nicht, Upstream down |

Zu einzelnen Services:
- **Firmware** vergleicht die installierte Version mit der neuesten aus der Update-Prüfung der OPNsense
  (`/tmp/pkg_upgrade.json`, entsteht bei System › Firmware › Updates prüfen bzw. dem täglichen Cron-Job). Ab 1.2.17
  stört ein fehlendes oder kaputtes Changelog (`/usr/local/opnsense/changelog/index.json`) nicht mehr. Reine
  Paket-Updates ohne neue OPNsense-Version meldet der Service nicht
  ([Bekannte Probleme](../03-fehlerbehebung/02-bekannte-probleme.md)).
- **Services** fragt die Dienste ab, die die OPNsense unter System › Diagnose › Dienste zeigt. Ab 1.2.18 dürfen
  Dienste, die in `skipservice` stehen, gestoppt sein, ohne dass der Service CRIT wird; der Text nennt sie
  (`stopped, ignored: …`). Angegeben wird der Name oder die Beschreibung aus der Dienste-Liste, Groß- und
  Kleinschreibung egal:
  ```
  skipservice: ntopng,HAProxy Load Balancer
  ```
- **Audit:** `pkg audit` vergleicht die installierten Pakete mit der Liste bekannter Sicherheitslücken. Die Warnung
  verschwindet, wenn die OPNsense ein korrigiertes Paket ausliefert; Details zeigt `pkg audit -F` auf der Shell.
- **CARP:** Ein Knoten mit `advskew` unter 50 soll MASTER sein, einer mit 50 oder mehr BACKUP. Der Text zeigt den
  Demotion-Level (`demotion:`, `sysctl net.inet.carp.demotion`).
- **Gateway:** nur Gateways mit eingeschalteter Überwachung (dpinger). Metriken: Laufzeit, Abweichung, Verlust.
- **OpenVPN:** Instanzen (VPN › OpenVPN › Instanzen) und das alte Modell („Legacy“, ab OPNsense 26.1 im Plugin
  `os-openvpn-legacy`), auch beide nebeneinander. Server mit mehreren Clients ergeben `OpenVPN Server: <Name>` mit
  der Zahl der Verbindungen; Client-Instanzen, Legacy-Clients und Peer-to-Peer-Server ergeben
  `OpenVPN Connection: <Name>`. Clients mit einem Client-Overwrite (Client-spezifische Einstellungen) erscheinen
  zusätzlich als `OpenVPN Client: <Name>`. Deaktivierte Tunnel erscheinen nicht.
- **IPsec:** nur wenn IPsec eingeschaltet ist. Alte Tunnel (Phase 1/2) und ab 1.2.18 die Verbindungen
  (VPN › IPsec › Verbindungen, swanctl). Name ist die Beschreibung, sonst die Gegenstelle. Bei Verbindungen müssen
  alle eingeschalteten Children aufgebaut sein; fehlt eins, nennt der Text es. `not connected (CONNECTING)` heißt:
  die Gegenstelle antwortet nicht, `not connected (ESTABLISHED)`: IKE steht, aber kein Child. Deaktivierte Tunnel
  und Verbindungen erscheinen nicht.
- **NetBird** ab 1.2.18, wenn NetBird eingeschaltet ist (Plugin `os-netbird` oder `netbird_enable` in `rc.conf`): ein Service für den Daemon und je
  Peer einer, aus `netbird status --json`. Metriken: verbundene, gesamte und über Relay verbundene Peers; je Peer
  Latenz, Alter des letzten Handshakes und Traffic.
- **Geändert in 1.2.18 (OpenVPN):** Bis 1.2.17 fehlten Instanzen ganz oder der Check scheiterte (mehrere
  Instanzen, Client-Instanzen, ein einzelner Legacy-Server). Ab 1.2.18 erscheinen alle; nach dem Update in Checkmk
  die Service-Erkennung ausführen. Ein Server, dessen Prozess nicht läuft, ist CRIT mit „Server down“.
- **WireGuard** ab 1.2.18: Peers ohne Endpoint-Adresse (Roadwarrior: Handy, Laptop) sind nur verbunden, solange sie
  genutzt werden; getrennt bleiben sie OK. Deaktivierte Peers und Peers nur an deaktivierten Instanzen erscheinen
  nicht. Der Text beginnt mit `online` oder `offline`.

:::info
**Geändert in 1.2.18:** Bis 1.2.17 war jeder WireGuard-Peer ohne Handshake seit 5 Minuten CRIT, auch Roadwarrior und
deaktivierte Peers. Nach dem Update in Checkmk die Service-Erkennung ausführen: Services deaktivierter Peers
verschwinden.
:::

## Abschnitte
| `skipcheck` | Abschnitt | Inhalt | Voraussetzung |
|---|---|---|---|
| `cpu`, `kernel`, `uptime` | `cpu`, `kernel`, `uptime` | Last, CPU-Zeiten, Kontextwechsel, Laufzeit | – |
| `mem` | `statgrab_mem` | Speicher und Swap | – |
| `df`, `mounts` | `df`, `mounts` | Dateisysteme | – |
| `zpool`, `zfs` | `zpool_status`, `zfs_arc_cache`, `zfsget` | ZFS-Pools, ARC, Datasets | ZFS-Installation |
| `net` | `statgrab_net` | zugewiesene Interfaces, WireGuard-Instanzen; ab 1.2.18 auch laggs und ihre Member | – |
| `netctr`, `tcp` | `netctr`, `tcp_conn_stats` | Zähler, TCP-Verbindungen | – |
| `ps` | `ps` | Prozesse (für Process Discovery in Checkmk) | – |
| `ntp` | `ntp` | Zeitsynchronisation | NTP-Dienst |
| `temperature` | `lnx_thermal` | Temperatur-Sensoren | Sensoren per `sysctl` |
| `ssh` | `sshd_config` | SSH-Einstellungen | SSH eingeschaltet |
| `label` | `labels` | Label `cmk/device_type:vm` in einer VM | – |
| `dhcp` | `isc_dhcpd` | DHCP-Pools und aktive Leases; ab 1.2.18 auch von Kea DHCPv4 | ISC-DHCP oder Kea (in der OPNsense eingeschaltet); nicht Dnsmasq-DHCP |
| `haproxy` | `haproxy` | Frontends, Backends, Server | Plugin `os-haproxy` |
| `squid` | `squid` | Proxy-Statistik | Web-Proxy eingeschaltet und auf 127.0.0.1 erreichbar; [Squid-MKP](https://exchange.checkmk.com/p/squid) in Checkmk |
| `smartinfo` | `disk_smart_info` | SMART-Werte der Festplatten | Plugin `os-smart`; [checkmk-smart-MKP](https://github.com/bashclub/checkmk-smart) in Checkmk |
| `ipmi` | `ipmi` | IPMI-Sensoren | `ipmitool` installiert |
| `apcupsd` | `apcaccess` | USV | Plugin `os-apcupsd` |
| `taskdir` | – | Tasks ([Erweiterungen](03-erweiterungen.md#tasks)) | Task-Dateien |

Dazu die Inventur (HW/SW-Inventory) und der Abschnitt `check_mk` mit Version, Hostname und `FailedPythonPlugins`
([Diagnose](../03-fehlerbehebung/01-diagnose.md)).

:::info
**Ab 1.2.18** erscheinen laggs und ihre Member (z. B. `lagg0_ix0`) als Interfaces, auch wenn nur VLANs darauf
zugewiesen sind. Nach dem Update bietet die Service-Erkennung sie als neue Interface-Services an.
:::
