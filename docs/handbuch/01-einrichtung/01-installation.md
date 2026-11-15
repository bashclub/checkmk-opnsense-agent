---
title: Installation
audience: Admin
outline:
---
Der Agent ist eine einzelne Python-Datei. Python und die nötigen Module bringt die OPNsense mit, ein Paket gibt es
nicht. Er läuft als Dienst (Daemon) und antwortet auf TCP-Port 6556, wie der Checkmk-Agent unter Linux.

Die Befehle im Handbuch sind für `sh` geschrieben. Die Shell von root auf der OPNsense ist `csh`; dort zuerst `sh`
eingeben.

## Herunterladen und starten
Auf der OPNsense als root (SSH oder Konsole, Menüpunkt 8 „Shell“):
```sh
fetch -o /usr/local/etc/rc.syshook.d/start/99-checkmk_agent https://code.bashclub.org/bashclub/checkmk-opnsense-agent/raw/branch/main/opnsense_checkmk_agent.py
chmod +x /usr/local/etc/rc.syshook.d/start/99-checkmk_agent
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent
```
Der letzte Befehl startet den Dienst. Prüfen:
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --status
```
```
running
```

## Autostart
Der Pfad ist Absicht: Skripte unter `/usr/local/etc/rc.syshook.d/start/` startet die OPNsense beim Booten. Ohne
Option aufgerufen erkennt der Agent diesen Ort und startet sich als Dienst. Liegt die Datei woanders, startet ihn
`--start`, aber nicht beim Booten.

## Firewall-Regel
Der Checkmk-Server muss die OPNsense auf TCP-Port 6556 erreichen. Auf dem Interface, über das der Checkmk-Server kommt,
eine Regel anlegen (Firewall › Regeln › Interface):

| Feld | Wert |
|---|---|
| Aktion | Erlauben |
| Protokoll | TCP |
| Quelle | IP-Adresse des Checkmk-Servers |
| Ziel | Diese Firewall |
| Zielport | 6556 |

Auf LAN erlaubt die Standardregel den Zugriff schon. Der Agent selbst antwortet auf allen Interfaces; wer den Zugriff
auch im Agent beschränken will, setzt `onlyfrom` (siehe [An Checkmk anbinden](02-checkmk-anbinden.md)). Port 6556
auf WAN nicht öffnen.

## Testen
Auf der OPNsense selbst, ohne Netzwerk:
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --debug | head -20
```
Vom Checkmk-Server aus, als Site-Benutzer (`firewall.example.org` durch die Adresse der OPNsense ersetzen):
```sh
FW=firewall.example.org
nc -w 20 "$FW" 6556 | head -5
```
```
<<<check_mk>>>
AgentOS: OPNsense
Version: 1.2.18
Hostname: firewall.example.org
```

## Deinstallieren
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --stop
rm /usr/local/etc/rc.syshook.d/start/99-checkmk_agent /usr/local/etc/checkmk.conf
```
