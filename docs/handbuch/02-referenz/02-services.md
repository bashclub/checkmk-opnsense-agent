---
title: Services und Zustände
audience: Anwender, Admin
outline: https://docs.bashclub.org/doc/services-und-zustande-PG5WxCx4Yc
outline_id: 2d2853da-823b-4ec6-86d6-f389e061c920
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
| `firmware` | `Firmware` | aktuelle Version | Update verfügbar (auch Major-Upgrade und ab 1.2.18 Paket-Updates) | – |
| `business` | `Business Licence` | Lizenz läuft länger als 60 Tage | unter 60 Tagen | unter 30 Tagen |
| `agentupdate` | `Checkmk Agent Update` | Agent aktuell oder keine Prüfung möglich | neue Version ([Updates](../01-einrichtung/03-updates.md)) | – |
| `services` | `Services` | alle Dienste der OPNsense laufen | – | ein Dienst läuft nicht |
| `pkgaudit` | `Audit` | `pkg audit` findet nichts | Pakete mit bekannten Sicherheitslücken | – |
| `carpstatus` | `CARP: <Interface>@<VHID>` | erwarteter Zustand | anderer Zustand | – |
| `gateway` | `Gateway <Name>` | ohne Verlust, Laufzeit bis 100 ms | Verlust oder Laufzeit über 100 ms | Verlust über 90 % oder keine Daten |
| `openvpn` | `OpenVPN Server: <Name>`, `OpenVPN Client: <Name>`, `OpenVPN Connection: <Name>` | läuft bzw. verbunden | wartet auf Verbindung; Zertifikat läuft in unter 61 Tagen ab | Server down, nicht verbunden; Zertifikat in unter 31 Tagen |
| `ipsec` | `IPsec Tunnel: <Name>` | Tunnel aufgebaut mit Phase 2 bzw. allen Children | ab 1.2.18: nur ein Teil der Children einer Verbindung aufgebaut | nicht verbunden, IPsec läuft nicht |
| `wireguard` | `WireGuard Client: <Name>` | verbunden; Roadwarrior auch getrennt | – | Site-to-Site ohne Handshake seit 5 min; Instanz läuft nicht |
| `netbird` | `NetBird`, `NetBird Peer: <Name>` | ab 1.2.18: Daemon, Management und Signal verbunden; Peer verbunden | Management oder Signal getrennt; Peer `Connecting` oder Handshake älter als 5 min | Daemon nicht verbunden (z. B. `NeedsLogin`), keine Daten; Peer getrennt |
| `disks` | `Disks`, `Disk <Seriennummer> SMART`, `Disk <Seriennummer> Wearout` | ab 1.2.19: SMART in Ordnung; Restlebensdauer über 20 % | Zähler gestiegen, NVMe-Reserve knapp; Lebensdauer unter 20 % oder Prognose unter 180 Tagen | Selbstdiagnose FAILED, Attribut unter Schwelle, Selbsttest fehlgeschlagen; Lebensdauer unter 10 % oder Prognose unter 60 Tagen |
| `unbound` | `Unbound DNS` | läuft, mit Anfragen und Cache-Treffern | – | läuft nicht |
| `certificates` | `Certificate: <Name>`, `CA: <Name>` | ab 1.2.18: läuft noch 30 Tage oder länger | unter 30 Tagen | unter 14 Tagen oder abgelaufen |
| `acmeclient` | `ACME Cert: <Name>` | Zertifikat erneuert | ausstehend | Fehler, Ablauf in unter 10 Tagen |
| `caddy` | `Caddy Domain: <Domain>` | ab 1.2.18: Upstreams erreichbar, Zertifikat erneuert | ein Teil der Upstreams nicht erreichbar; Zertifikat überfällig oder noch keins | kein Upstream erreichbar; Zertifikat (fast) abgelaufen |
| `nginx` | `Nginx Uptime`, `Nginx Location: <Name>` | läuft, Upstreams erreichbar | Upstream teilweise erreichbar, keine Daten | nginx läuft nicht, Upstream down |

Zu einzelnen Services:
- **Firmware** vergleicht die installierte Version mit der neuesten aus der Update-Prüfung der OPNsense
  (`/tmp/pkg_upgrade.json`, entsteht bei System › Firmware › Updates prüfen bzw. dem täglichen Cron-Job). Ab 1.2.17
  stört ein fehlendes oder kaputtes Changelog (`/usr/local/opnsense/changelog/index.json`) nicht mehr. Ab 1.2.18
  meldet er auch Updates von Plugins und Paketen ohne neue OPNsense-Version (WARN, Metrik `package_updates`, bis zu
  10 Paketnamen im Text).
- **Services** fragt die Dienste ab, die die OPNsense unter System › Diagnose › Dienste zeigt. Ab 1.2.18 dürfen
  Dienste, die in `skipservice` stehen, gestoppt sein, ohne dass der Service CRIT wird; der Text nennt sie
  (`stopped, ignored: …`). Angegeben wird der Name oder die Beschreibung aus der Dienste-Liste, Groß- und
  Kleinschreibung egal:
  ```
  skipservice: ntopng,HAProxy Load Balancer
  ```
- **Audit:** `pkg audit` vergleicht die installierten Pakete mit der Liste bekannter Sicherheitslücken. Die Warnung
  verschwindet, wenn die OPNsense ein korrigiertes Paket ausliefert; Details zeigt `pkg audit -F` auf der Shell.
- **CARP:** Ein Knoten mit `advskew` unter 50 soll MASTER sein, einer mit 50 oder mehr BACKUP; empfohlen sind 0 auf
  dem ersten und 100 auf dem zweiten Knoten. Haben beide Knoten `advskew` unter 50, ist der CARP-Service auf dem
  Backup-Knoten WARN; ab 1.2.18 nennt der Text dann den erwarteten Zustand (`expected MASTER (advskew 1 < 50)`).
  Der Text zeigt außerdem den Demotion-Level (`demotion:`, `sysctl net.inet.carp.demotion`).
- **VPN auf dem CARP-Backup-Knoten:** Ab 1.2.18 sind OpenVPN- und IPsec-Tunnel, die an eine CARP-VIP gebunden sind,
  auf dem Knoten OK, auf dem diese VIP nicht MASTER ist; der Text beginnt mit `CARP BACKUP on <VIP> …, tunnel only
  runs on the master:`. Gebunden heißt: OpenVPN-Instanz mit „CARP Depend on“ oder lokaler Adresse der VIP, alter
  OpenVPN-Tunnel auf einem VIP-Interface, IPsec-Verbindung mit der VIP als lokaler Adresse, alter IPsec-Tunnel auf
  einem VIP-Interface. Andere Tunnel werden auf beiden Knoten normal bewertet.
- **Certificate/CA** ab 1.2.18: jedes Zertifikat unter System › Sicherheit › Zertifikate und jede eigene CA (mit
  privatem Schlüssel) unter Autoritäten, Name ist die Beschreibung. Metrik `expiredays`; die Schwellwerte 30/14 Tage
  gibt der Agent mit, Checkmk bewertet sie. Nicht dabei: importierte CAs ohne Schlüssel (z. B. die
  Zwischenzertifikate R10, R11 … des ACME-Clients), Zertifikate des ACME-Clients (überwacht `ACME Cert`) und
  Zertifikate, die seit mehr als 30 Tagen abgelaufen sind (werden offensichtlich nicht mehr genutzt). Alte Zertifikate (z. B.
  von ausgeschiedenen VPN-Benutzern) nimmt `skipcert` aus: Beschreibung, CN oder refid, durch Komma getrennt:
  ```
  skipcert: VPN alice,bob.example.org
  ```
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
  Latenz, Alter des letzten Handshakes und Traffic. Ein Peer im Zustand `Idle` (offline, z. B. ein Laptop, oder eine
  Lazy Connection, die gerade nicht gebraucht wird) ist OK; mit `netbird_idle: warn` bzw. `crit` wird er WARN bzw.
  CRIT, etwa wenn alle Peers Standortverbindungen sind.
- **Geändert in 1.2.18 (OpenVPN):** Bis 1.2.17 fehlten Instanzen ganz oder der Check scheiterte (mehrere
  Instanzen, Client-Instanzen, ein einzelner Legacy-Server). Ab 1.2.18 erscheinen alle; nach dem Update in Checkmk
  die Service-Erkennung ausführen. Ein Server, dessen Prozess nicht läuft, ist CRIT mit „Server down“.
- **Caddy** ab 1.2.18 (Plugin `os-caddy`, eingeschaltet): ein Service je Domain des Reverse Proxy. Der Agent prüft
  selbst per TCP-Verbindung, ob die Ziele der Handles (auch der Subdomains) erreichbar sind, und liest das
  Zertifikat, das Caddy für die Domain verwaltet (`/var/db/caddy/data/caddy/certificates`). Caddy erneuert bei einem
  Drittel Restlaufzeit; bleibt weniger als ein Sechstel, ist der Service WARN, unter einem Zwölftel CRIT. Das passt für
  Let's Encrypt (90 Tage) wie für die interne CA von Caddy (12 Stunden). Domains mit eigenem Zertifikat überwacht
  `Certificate`. Metriken: erreichbare und alle Upstreams, `expiredays`.
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
| `dhcp` | `isc_dhcpd` | DHCPv4-Pools und aktive Leases; ab 1.2.18 auch von Kea und Dnsmasq | ISC-DHCP, Kea oder Dnsmasq (eingeschaltet, mit DHCP-Bereich) |
| `haproxy` | `haproxy` | Frontends, Backends, Server | Plugin `os-haproxy` |
| `squid` | `squid` | Proxy-Statistik | Web-Proxy eingeschaltet und auf 127.0.0.1 erreichbar; [Squid-MKP](https://exchange.checkmk.com/p/squid) in Checkmk |
| `smartinfo` | `disk_smart_info` | SMART-Werte der Festplatten | Plugin `os-smart`; [checkmk-smart-MKP](https://github.com/bashclub/checkmk-smart) in Checkmk (Alternative siehe unten) |
| `ipmi` | `ipmi` | IPMI-Sensoren | `ipmitool` installiert |
| `apcupsd` | `apcaccess` | USV | Plugin `os-apcupsd` |
| `taskdir` | – | Tasks ([Erweiterungen](03-erweiterungen.md#tasks)) | Task-Dateien |

**Platten (`disks`)** ab 1.2.19, nur wenn `smartctl` installiert ist (Plugin `os-smart`), wie „PVE Disks“ des
cmk-push-agent:
- `Disks`: Zahl der physischen Platten (aus `smartctl --scan-open`; doppelt gelistete NVMe wie `nda0`/`nvme0` nur
  einmal). In einer VM gibt es keine Services.
- `Disk <Seriennummer> SMART`: nur, was `smart_posix` von Checkmk nicht auswertet – Ergebnis der Selbstdiagnose,
  Attribute unter der Herstellerschwelle (Temperatur als Kühlproblem), letzter Selbsttest (abgebrochene Tests sind
  kein Fehler), Anstieg der Zähler 198, SAS Grown Defects und SAS-Fehler (WARN eine Woche lang), NVMe-Reserve
  weniger als 10 Punkte über der Schwelle. Bei einem Befund steht die Abhilfe im Text, bei ZFS mit dem Pool.
- `Disk <Seriennummer> Wearout` (SSD/NVMe): Restlebensdauer (NVMe Percentage Used bzw. SMART-Attribut 177, 231,
  233, 202, 169, 173) mit Prognose aus dem Verlauf, sobald sie über mindestens 30 Tage um 2 Punkte gesunken ist.
Die Werte werden 30 Minuten zwischengespeichert, schlafende Platten nicht geweckt; der Verlauf liegt in
`/var/lib/check_mk_agent/disks.json`. Der Name nutzt die Seriennummer, weil sich `/dev/ada0` beim Tausch ändern kann.

**SMART ohne MKP:** Nach Rückmeldung von Nutzern (#83) funktioniert das Standard-Plugin `smart_posix` aus Checkmk
auf der OPNsense: Plugin `os-smart` installieren (bringt `smartctl`), `smart_posix` aus dem Checkmk-Server
(Setup › Agents › Linux, Datei `smart_posix`) nach `/usr/local/check_mk_agent/plugins/` kopieren und ausführbar machen,
den eigenen Abschnitt mit `skipcheck: smartinfo` abschalten und die Service-Erkennung ausführen. Auf der Test-VM ist
das nicht geprüft (virtuelle Platten haben kein SMART).

Dazu die Inventur (HW/SW-Inventory) und der Abschnitt `check_mk` mit Version, Hostname und `FailedPythonPlugins`
([Diagnose](../03-fehlerbehebung/01-diagnose.md)).

:::info
**Ab 1.2.18** erscheinen laggs und ihre Member (z. B. `lagg0_ix0`) als Interfaces, auch wenn nur VLANs darauf
zugewiesen sind. Nach dem Update bietet die Service-Erkennung sie als neue Interface-Services an.
:::
