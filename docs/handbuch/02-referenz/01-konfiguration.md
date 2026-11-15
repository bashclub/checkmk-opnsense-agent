---
title: Konfiguration und Kommandozeile
audience: Admin
outline:
---
## Konfigurationsdatei
`/usr/local/etc/checkmk.conf`, eine Option je Zeile, `name: wert`. Zeilen mit `#` am Anfang sind Kommentare, ebenso
der Rest einer Zeile ab ` #` (Leerzeichen und `#`; deshalb gehört diese Folge nicht in ein Passwort). Die Datei ist
optional. Änderungen gelten nach `--restart`. Bei mehrfach genannten Optionen gilt die letzte Zeile.

```
port: 6556
onlyfrom: 192.0.2.10,2001:db8::10
encrypt: ein-langes-zufaelliges-passwort
skipcheck: agentupdate,ipmi
```

| Option | Standard | Bedeutung |
|---|---|---|
| `port` | `6556` | TCP-Port des Agents |
| `onlyfrom` | alle | nur diese IP-Adressen bekommen Daten, durch Komma getrennt, ohne Netze ([An Checkmk anbinden](../01-einrichtung/02-checkmk-anbinden.md#zugriff-beschränken-onlyfrom)) |
| `encrypt` | aus | Passwort für die verschlüsselte Ausgabe ([An Checkmk anbinden](../01-einrichtung/02-checkmk-anbinden.md#verschlüsselung)) |
| `skipcheck` | keine | Checks, die nicht laufen, durch Komma getrennt; die Namen stehen in [Services und Zustände](02-services.md) |
| `expire_inventory` | `14400` | Sekunden, nach denen ein Abrufer wieder die Inventur bekommt |
| `tenants` | keine | Abrufer, die nur Task-Daten bekommen ([Erweiterungen](03-erweiterungen.md#tenants)) |
| `localdir` | `/usr/local/check_mk_agent/local` | Verzeichnis für eigene lokale Checks |
| `plugindir` | `/usr/local/check_mk_agent/plugins` | Verzeichnis für eigene Plugins |
| `spooldir` | `/var/lib/check_mk_agent/spool` | Verzeichnis für Spool-Dateien |

Kommandozeilen-Optionen (`--port`, `--encrypt`, …) gelten nur, wenn die Option nicht in der Datei steht; Ausnahme
`--encrypt`, das Vorrang vor der Datei hat. Für den Betrieb die Datei nutzen.

## Kommandozeile
`/usr/local/etc/rc.syshook.d/start/99-checkmk_agent` mit:

| Aufruf | Wirkung |
|---|---|
| ohne Option | startet den Dienst, wenn die Datei unter `rc.syshook.d/start/` liegt (Boot) |
| `--start`, `--stop`, `--restart`, `--status` | Dienst steuern |
| `--nodaemon` | im Vordergrund laufen, zum Testen |
| `--debug` | Ausgabe einmal auf der Konsole, unverschlüsselt, mit den Fehlermeldungen der Checks |
| `--checkoutput [host]` | den laufenden Agent abfragen (Standard `127.0.0.1`) und mit `encrypt` entschlüsseln |
| `--configdebug` | `/conf/config.xml` so, wie der Agent sie liest, als JSON |
| `--zabbix` | nur die lokalen Checks als JSON |
| `--update [testing]` | Agent aktualisieren ([Updates](../01-einrichtung/03-updates.md)) |
| `--config datei` | andere Konfigurationsdatei |
| `--pidfile datei` | PID-Datei, Standard `/var/run/checkmk_agent.pid` |
| `-h`, `--help` | Hilfe, aktive Konfiguration und gefundene Tasks |

## Dateien
| Pfad | Inhalt |
|---|---|
| `/usr/local/etc/rc.syshook.d/start/99-checkmk_agent` | der Agent |
| `/usr/local/etc/checkmk.conf` | Konfiguration |
| `/var/run/checkmk_agent.pid` | PID des Dienstes |
| `/usr/local/check_mk_agent/{local,plugins,tasks}` | Erweiterungen |
| `/var/lib/check_mk_agent/spool` | Spool-Dateien |

Meldungen schreibt der Agent ins Systemlog (`checkmk_agent`, Facility `daemon`), zu sehen unter
System › Protokolldateien › Allgemein.
