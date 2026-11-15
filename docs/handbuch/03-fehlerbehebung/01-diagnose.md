---
title: Diagnose
audience: Admin
outline: https://docs.bashclub.org/doc/diagnose-zp0w6NLXlL
outline_id: e20cbd17-d0b5-49ad-96ce-63367cd82df1
---
## Läuft der Agent?
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --status
sockstat -l -p 6556
```
Läuft er nicht, startet ihn `--start`. Startet er nicht, im Vordergrund starten und die Fehlermeldung lesen:
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --nodaemon
```
(Abbrechen mit Strg+C.)

## Liefert er Daten?
`--debug` führt alle Checks einmal aus, unverschlüsselt, und schreibt zuerst die Fehlermeldungen (Python-Tracebacks)
der Checks, die gescheitert sind:
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --debug > /tmp/agent.txt
head -40 /tmp/agent.txt
grep FailedPythonPlugins /tmp/agent.txt
```
`FailedPythonPlugins: openvpn,ipsec` nennt die Checks, die gescheitert sind; Checkmk zeigt die Zeile im Service
`Check_MK` bzw. `Check_MK Agent`. Die übrigen Checks liefern trotzdem. Einen fehlerhaften Check bis zum Fix mit
`skipcheck` abschalten ([Konfiguration](../02-referenz/01-konfiguration.md)).

Den laufenden Dienst so abfragen, wie Checkmk es tut (entschlüsselt mit `encrypt` aus der Config):
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --checkoutput | head -20
```

## Checkmk bekommt nichts
| Symptom | Ursache | Abhilfe |
|---|---|---|
| Zeitüberschreitung | Firewall-Regel fehlt | Regel für TCP 6556 vom Checkmk-Server ([Installation](../01-einrichtung/01-installation.md#firewall-regel)) |
| Verbindung wird sofort geschlossen, keine Daten | `onlyfrom` nennt den Checkmk-Server nicht; bis 1.2.17 jeder IPv4-Client | Systemlog: `Client … not allowed`; Adresse prüfen, ab 1.2.18 aktualisieren ([An Checkmk anbinden](../01-einrichtung/02-checkmk-anbinden.md#zugriff-beschränken-onlyfrom)) |
| „Unsupported agent output“, unlesbare Daten | Agent verschlüsselt, Checkmk nicht (oder umgekehrt, anderes Passwort) | Regel „Symmetric encryption“ in Checkmk und `encrypt` vergleichen |
| Leere Ausgabe nach Firmware-Update auf 26.7.9 | kaputtes Changelog der OPNsense (bis Agent 1.2.16) | auf 1.2.17 oder neuer aktualisieren |

Das Systemlog des Agents:
```sh
grep checkmk_agent /var/log/system/latest.log | tail -20
```

## Ein Service fehlt oder stimmt nicht
1. Liefert der Agent ihn? `--debug | grep "Name des Service"`.
2. Steht der Check in `skipcheck`? `--help` zeigt die aktive Konfiguration.
3. Ist die Funktion auf der OPNsense eingeschaltet (z. B. IPsec, Web-Proxy, SSH)? Abgeschaltetes liefert keinen
   Service.
4. In Checkmk die Service-Erkennung ausführen: Neue Services (neue Tunnel, Peers, Interfaces) erscheinen erst danach.
5. Steht der Fehler in [Bekannte Probleme](02-bekannte-probleme.md)?
