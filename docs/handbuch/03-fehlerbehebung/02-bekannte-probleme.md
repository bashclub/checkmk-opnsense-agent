---
title: Bekannte Probleme
audience: Admin
outline:
---
Offene Fehler und Einschränkungen, mit Umgehung, soweit es eine gibt. Behobene Fehler verschwinden von dieser Seite;
was sich dadurch im Betrieb ändert, steht mit Versionsvermerk im jeweiligen Artikel.

## Firmware
- Updates nur für Pakete oder Plugins (ohne neue OPNsense-Version) meldet der Service `Firmware` nicht.

## CARP
- Auf dem Backup-Knoten eines Clusters sind VPN-Tunnel, die nur auf dem Master laufen, CRIT. Der Agent berücksichtigt
  den CARP-Zustand dabei nicht. Umgehung: die Services auf dem Backup-Knoten in Checkmk per Regel deaktivieren oder
  ihren Zustand anpassen.

## DHCP
- DHCP über Dnsmasq (Standard bei neuen Installationen) erscheint nicht; ISC-DHCP und ab 1.2.18 Kea schon.

## Hilfetext
- `--help` und der Kopf der Datei verweisen für SMART noch auf das MKP `checkmk-smart`. Nach Rückmeldungen funktioniert
  auch das Standard-Plugin `smart_posix` aus Checkmk in `/usr/local/check_mk_agent/plugins/` mit dem Plugin
  `os-smart`; beides ist noch nicht getestet und dokumentiert.
