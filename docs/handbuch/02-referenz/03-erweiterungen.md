---
title: Erweiterungen
audience: Admin
outline: https://docs.bashclub.org/doc/erweiterungen-0krJek1taw
outline_id: 754e2698-f69f-42d5-a241-08e6bcd11078
---
## Eigene Plugins und lokale Checks
Wie beim Linux-Agent führt der Agent bei jeder Abfrage ausführbare Dateien aus zwei Verzeichnissen aus und hängt ihre
Ausgabe an:

| Verzeichnis | Ausgabe |
|---|---|
| `/usr/local/check_mk_agent/plugins` | ganze Abschnitte (`<<<name>>>` …), z. B. Plugins aus Checkmk |
| `/usr/local/check_mk_agent/local` | lokale Checks im Checkmk-Format: `Zustand "Service" Metriken Text` |

Unterverzeichnisse dürfen sein. Heißt das Verzeichnis einer Datei wie eine Zahl, cacht der Agent ihre Ausgabe so viele
Sekunden, z. B. `/usr/local/check_mk_agent/local/3600/mein_check` einmal pro Stunde. Nur Dateien mit
Ausführungsrecht laufen:
```sh
mkdir -p /usr/local/check_mk_agent/local
cat > /usr/local/check_mk_agent/local/hallo <<'EOF'
#!/bin/sh
echo '0 "Hallo Welt" - Der lokale Check läuft'
EOF
chmod +x /usr/local/check_mk_agent/local/hallo
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --debug | grep Hallo
```
```
0 "Hallo Welt" - Der lokale Check läuft
```

## Spool
Dateien in `/var/lib/check_mk_agent/spool` hängt der Agent unverändert an die Ausgabe an; so können Cron-Jobs oder
Skripte Ergebnisse ablegen, ohne bei jeder Abfrage zu laufen. Die Datei enthält fertige Abschnitte, für lokale Checks
also mit der Zeile `<<<local:sep(0)>>>` davor. Ab 1.2.18 gilt wie beim Linux-Agent: Eine Datei `600_name` wird nur
600 Sekunden nach ihrer letzten Änderung ausgeliefert, danach nicht mehr (veraltete Ergebnisse).

## Tasks
Tasks sind Prüfungen, die der Agent im Hintergrund in eigenem Takt ausführt und deren letztes Ergebnis er mitliefert.
Sie sind **experimentell**; `blocklist` ist auf der Test-VM geprüft. Eine Task ist eine Datei `/usr/local/check_mk_agent/tasks/<name>.task`
mit Zeilen `schlüssel: wert`; der Agent liest das Verzeichnis alle 10 Minuten neu, `--help` zeigt die gefundenen Tasks.

| Schlüssel | Bedeutung |
|---|---|
| `type` | `blocklist`, `domain`, `nmap` (die Typen `proxy`, `speedtest` und `ssh` gibt es, sie tun aber noch nichts) |
| `interval` | Sekunden zwischen zwei Läufen, Standard 3600 |
| `hostname`, `ipaddress`, `domain`, `port`, `service` | Ziel der Prüfung, je nach Typ |
| `piggyback` | Ergebnis einem anderen Host in Checkmk zuordnen (Piggyback) |
| `tenant` | nur diese Tenants (IP-Adressen, durch Komma getrennt) bekommen das Ergebnis |

- **`blocklist`** prüft, ob IP-Adressen (`ipaddress`, durch Komma getrennt, oder die A-Records von `hostname`) auf
  DNS-Blocklisten stehen, und liefert einen lokalen Check (CRIT, wenn gelistet).
- **`domain`** prüft SOA, Nameserver, MX, TLSA und PTR einer `domain` und liefert den Abschnitt `domaincheck`.
- **`nmap`** scannt `hostname` auf offene Ports und liefert den Abschnitt `nmap`; braucht `nmap` auf der OPNsense.

Für `domaincheck` und `nmap` gibt es in Checkmk keine Standard-Plugins; sie brauchen eigene Check-Plugins.

Beispiel, die WAN-Adresse der Firewall auf Blocklisten prüfen:
```sh
WANIP=198.51.100.1
mkdir -p /usr/local/check_mk_agent/tasks
printf 'type: blocklist\nipaddress: %s\nservice: WAN\ninterval: 3600\n' "$WANIP" > /usr/local/check_mk_agent/tasks/blocklist-wan.task
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --restart
```
Nach dem ersten Lauf (einige Sekunden) erscheint der Service `Blocklist WAN`: OK, wenn die Adresse auf keiner der
rund 45 Listen steht, sonst CRIT mit den Listen. Private Adressen stehen auf der Bogon-Liste. Der Service
`CMK Tasks` zeigt, wie viele Tasks es gibt, wie viele gerade laufen und wie viele fehlgeschlagen sind.

## Tenants
Mit `tenants` bekommen bestimmte Abrufer **nur** die Ergebnisse der Tasks, die für sie bestimmt sind (Schlüssel
`tenant` in der Task), nicht die Daten der Firewall; z. B. ein Kunde, der in seinem eigenen Checkmk die Erreichbarkeit
seiner Dienste sehen soll. In `/usr/local/etc/checkmk.conf`, IP-Adresse und optional nach `#` ein eigenes Passwort
für die Verschlüsselung:
```
tenants: 192.0.2.20#passwort-des-kunden,192.0.2.21
```
Tenants dürfen abrufen, auch wenn `onlyfrom` sie nicht nennt.

:::info
**Fehler bis 1.2.17:** Ein Tenant ohne `#passwort` brachte den Agent beim Start zum Absturz, und IPv4-Tenants wurden
wie bei `onlyfrom` nicht erkannt. Behoben in 1.2.18.
:::
