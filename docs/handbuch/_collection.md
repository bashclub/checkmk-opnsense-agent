---
title: checkmk-opnsense-agent
audience: Anwender, Admin
outline:
---
**checkmk-opnsense-agent** ist ein Checkmk-Agent für OPNsense. Er besteht aus einer einzigen Python-Datei, läuft mit
dem Python der OPNsense und braucht kein Paket. Er liefert die üblichen Daten eines Checkmk-Agents (CPU, Speicher,
Dateisysteme, Interfaces, ZFS, Prozesse) und dazu Services für die OPNsense: Firmware- und Paket-Updates, Dienste,
CARP, Gateways, OpenVPN, IPsec, WireGuard, Unbound, ACME-Zertifikate, nginx und HAProxy. Die Ausgabe kann
verschlüsselt werden. Freie Software unter BSD-2-Clause.

Dieses Handbuch beschreibt Version 1.2.17 und später. Funktionen und Fixes ab 1.2.17 nennen ihre Version.

## Bereiche
1. [Einrichtung](01-einrichtung/_index.md) – Installation, Anbindung an Checkmk, Updates
2. [Referenz](02-referenz/_index.md) – Optionen, Services und Zustände, Erweiterungen
3. [Fehlerbehebung](03-fehlerbehebung/_index.md) – Diagnose, bekannte Probleme

Neu hier: [Installation](01-einrichtung/01-installation.md), dann
[An Checkmk anbinden](01-einrichtung/02-checkmk-anbinden.md).

## Kontakt

| ![](https://code.bashclub.org/bashclub/checkmk-opnsense-agent/raw/branch/main/docs/handbuch/logo-spille-it.png) | ![](https://code.bashclub.org/bashclub/checkmk-opnsense-agent/raw/branch/main/docs/handbuch/logo-bashclub.png) |
|:---:|:---:|
| **Spille IT Solutions** | **bashclub** |
| Thorsten Spille, bashclub-Kernteam, Maintainer von checkmk-opnsense-agent | Community rund um Proxmox, ZFS und Linux, entstanden bei der sysops GmbH |
| Kommerzieller Support, Einrichtung und Wartung | Videos: [YouTube-Kanal sysopstv](https://www.youtube.com/@sysopstv) |
| [spille-it.de](https://spille-it.de) | [code.bashclub.org](https://code.bashclub.org/bashclub/checkmk-opnsense-agent) |
| [kontakt@spille-it.de](mailto:kontakt@spille-it.de) | [github.com/bashclub](https://github.com/bashclub) |

**Fehler, Fragen, Wünsche:** Issues im Repository
[code.bashclub.org/bashclub/checkmk-opnsense-agent](https://code.bashclub.org/bashclub/checkmk-opnsense-agent/issues).
Zum Kommentieren ist ein Konto bei code.bashclub.org nötig, die Anmeldung geht auch mit einem GitHub-Konto. Das
Repository auf GitHub ist nur noch ein Spiegel.

Der Agent wurde von Nils Stöber für den bashclub entwickelt.

**Unterstützen**

| ![](https://code.bashclub.org/bashclub/checkmk-opnsense-agent/raw/branch/main/docs/handbuch/kofi-block.png) |
|:---:|
| [ko-fi.com/thorakel](https://ko-fi.com/A0A1J73JR) |

Die Artikel entstehen im Repository unter `docs/handbuch` und werden von dort hierher veröffentlicht. Korrekturen bitte
als Issue oder Pull Request.
