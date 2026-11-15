---
title: Bekannte Probleme
audience: Admin
outline:
---
Offene Fehler und Einschränkungen, mit Umgehung, soweit es eine gibt. Behobene Fehler verschwinden von dieser Seite;
was sich dadurch im Betrieb ändert, steht mit Versionsvermerk im jeweiligen Artikel.

## OpenVPN
- **Instanzen fehlen oder der Check scheitert.** Seit 1.2.16 gehen OpenVPN-Instanzen (VPN › OpenVPN › Instanzen) und
  ein einzelner Legacy-Server verloren; Client-Instanzen ohne Server und Server ohne Tunnelnetz lassen den Check
  scheitern (`FailedPythonPlugins: openvpn`). Ein Umbau des Checks ist in Arbeit.
- **Server nicht erreichbar:** Antwortet der Management-Socket eines Servers nicht, scheitert der ganze Check statt
  „Server down“ zu melden.

Umgehung: `skipcheck: openvpn`, bis der Umbau da ist.

## IPsec
- Nur das alte Tunnel-Modell (Phase 1/2). Verbindungen (VPN › IPsec › Verbindungen, swanctl) erscheinen nicht.
- Eine Phase 1 ohne Beschreibung lässt den Check scheitern. Umgehung: allen Phase-1-Einträgen eine Beschreibung geben.

## Firmware
- Updates nur für Pakete oder Plugins (ohne neue OPNsense-Version) meldet der Service `Firmware` nicht.

## CARP
- Auf dem Backup-Knoten eines Clusters sind VPN-Tunnel, die nur auf dem Master laufen, CRIT. Der Agent berücksichtigt
  den CARP-Zustand dabei nicht. Umgehung: die Services auf dem Backup-Knoten in Checkmk per Regel deaktivieren oder
  ihren Zustand anpassen.

## Prozesse
- Prozesse mit Prioritäts-Kennzeichen im Status (`S<`, `I<`, `SN` …) fehlen im Abschnitt `ps`. Process Discovery in
  Checkmk findet sie deshalb nicht.

## DHCP
- DHCP über Dnsmasq (Standard bei neuen Installationen) erscheint nicht; ISC-DHCP und ab 1.2.18 Kea schon.

## Tasks und Spool
- Tasks sind ungeprüft: Eine `blocklist`-Task erschien auf der Test-VM nach dem Neustart nicht in der Ausgabe.
- Lokale Checks aus Tasks setzen den Service-Namen in einfache statt doppelte Anführungszeichen; Checkmk übernimmt
  dann nur das erste Wort (mit `'`) als Namen.
- Das Präfix für das Höchstalter von Spool-Dateien (`600_name` wie beim Linux-Agent) wirkt nicht; Spool-Dateien
  werden immer ausgeliefert, auch wenn sie veraltet sind.

## Hilfetext
- `--help` und der Kopf der Datei verweisen für SMART noch auf das MKP `checkmk-smart`. Nach Rückmeldungen funktioniert
  auch das Standard-Plugin `smart_posix` aus Checkmk in `/usr/local/check_mk_agent/plugins/` mit dem Plugin
  `os-smart`; beides ist noch nicht getestet und dokumentiert.
