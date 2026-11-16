---
title: "Updates: Release und Testing"
audience: Admin
outline: https://docs.bashclub.org/doc/updates-release-und-testing-MHZE55In1Q
outline_id: 3d986dff-2427-4f28-b451-144f5f1e8432
---
Es gibt zwei Versionen des Agents, jeweils als Branch im Repository auf code.bashclub.org:

| Version | Branch | Für wen |
|---|---|---|
| Release | `main` | alle Firewalls im Betrieb |
| Testing | `testing` | zum Ausprobieren von Fixes, bevor sie ins Release kommen |

Fixes und neue Funktionen kommen zuerst nach `testing` und nach einer Prüfung ins Release.

## Update von Hand
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --update
```
Der Agent lädt die neue Version, zeigt die Versionen und fragt:
- `y` installiert die neue Version, danach fragt er, ob er den laufenden Dienst neu starten soll (`y`).
- `d` zeigt die Unterschiede zur installierten Datei.
- `n` bricht ab.

Die Testing-Version:
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --update testing
```
Zurück zum Release geht es mit `--update`; ist das Release älter, warnt der Agent vor dem Downgrade.

:::info
**Geändert in 1.2.17:** Bis 1.2.16 kamen Updates von GitHub. Ab 1.2.17 kommen sie von code.bashclub.org. Ein Agent
mit 1.2.16 oder älter holt sein Update noch von GitHub; dort liegt 1.2.17, danach geht es von code.bashclub.org weiter.
:::

## Automatisch aktualisieren
Ab 1.2.20 legt ein Aufruf einen Cronjob an, der jede Nacht um 3:00 auf das neueste Release aktualisiert:
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --install-cron
```
Der Job erscheint unter System › Einstellungen › Cron („Checkmk agent update (main)“) und lässt sich dort ändern oder
abschalten. Einen anderen Zeitplan gibt man im Cron-Format mit (Minute Stunde Tag Monat Wochentag), die Testing-Version
mit `--cron-branch testing`:
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --install-cron "30 4 * * 1" --cron-branch testing
```
Ein zweiter Aufruf ersetzt den Job. Entfernen:
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --uninstall-cron
```
Der Job ruft `--update --yes` auf: ohne Rückfragen, nur wenn die Version auf dem Server neuer ist (nie ein Downgrade,
z. B. wenn eine Testing-Version installiert ist und der Job das Release holt), nur wenn die neue Datei fehlerfrei
übersetzt; danach startet der Dienst neu. Das Ergebnis steht im Systemlog (`update: …`). Technisch legt
`--install-cron` die configd-Aktion `checkmkagent update` an
(`/usr/local/opnsense/service/conf/actions.d/actions_checkmkagent.conf`), denn die Cron-Seite der OPNsense kann nur
configd-Aktionen ausführen, keine Skripte.

## Service `Checkmk Agent Update`
Ab 1.2.17 prüft der Agent einmal am Tag, ob es eine neue Version gibt:

| Zustand | Bedeutung |
|---|---|
| OK | Version aktuell, oder keine Prüfung möglich (kein Internet) |
| WARN | Ein neues Release ist da; auf Testing auch eine neuere Testing-Version |

Ab 1.2.21 nennt der Text außerdem, ob das automatische Update eingerichtet ist und wann es läuft, z. B.
`auto update daily 03:00 (main)`, `auto update Mon,Wed 04:30 (testing)` oder `auto update off`; auf den Zustand hat das
keinen Einfluss. Fehlt die configd-Aktion zu einem Job, steht das ebenfalls dort.

Wer das Release nutzt, wird nur über Releases informiert. Ohne Internetzugang bleibt der Service OK und nennt den
Grund; nach einem Fehler versucht er es nach einer Stunde erneut. Die Abfrage geht an code.bashclub.org (HTTPS; gelesen
wird nur der Anfang der Datei mit der Versionsnummer).

Abschalten (z. B. bei Firewalls ohne Internet):
```sh
echo "skipcheck: agentupdate" >> /usr/local/etc/checkmk.conf
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --restart
```
Steht schon eine Zeile `skipcheck:` in der Datei, `agentupdate` dort mit Komma anhängen: Von mehreren Zeilen gilt nur
die letzte.
