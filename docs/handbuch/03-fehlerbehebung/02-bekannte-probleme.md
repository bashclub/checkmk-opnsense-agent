---
title: Bekannte Probleme
audience: Admin
outline:
---
Offene Fehler und Einschränkungen, mit Umgehung, soweit es eine gibt. Behobene Fehler verschwinden von dieser Seite;
was sich dadurch im Betrieb ändert, steht mit Versionsvermerk im jeweiligen Artikel.

## CARP
- Auf dem Backup-Knoten eines Clusters sind VPN-Tunnel, die nur auf dem Master laufen, CRIT. Der Agent berücksichtigt
  den CARP-Zustand dabei nicht. Umgehung: die Services auf dem Backup-Knoten in Checkmk per Regel deaktivieren oder
  ihren Zustand anpassen.

## DHCP
- DHCP über Dnsmasq (Standard bei neuen Installationen) erscheint nicht; ISC-DHCP und ab 1.2.18 Kea schon.
