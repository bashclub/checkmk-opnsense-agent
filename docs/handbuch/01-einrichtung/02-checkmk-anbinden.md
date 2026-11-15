---
title: An Checkmk anbinden
audience: Admin
outline: https://docs.bashclub.org/doc/an-checkmk-anbinden-xa1JS9mi5r
outline_id: 198adc82-18a5-4aba-9a17-8a5bad549e1d
---
## Host anlegen
In Checkmk die OPNsense wie einen Linux-Host anlegen (Setup › Hosts › Add host):
- **IP-Adresse** oder DNS-Name der OPNsense, über die der Checkmk-Server sie erreicht.
- **Checkmk agent / API integrations:** „API integrations if configured, else Checkmk agent“ (Standard).

Danach die Service-Erkennung (Discovery) ausführen und die Services übernehmen. Was die einzelnen Services bedeuten,
steht in [Services und Zustände](../02-referenz/02-services.md).

Die Hardware- und Software-Inventur (HW/SW-Inventory) liefert der Agent höchstens alle 4 Stunden je abfragender
IP-Adresse (`expire_inventory`).

## Zugriff beschränken: `onlyfrom`
Mit `onlyfrom` antwortet der Agent nur den genannten IP-Adressen, alle anderen Verbindungen schließt er ohne Daten.
In `/usr/local/etc/checkmk.conf` (die Datei anlegen, wenn sie fehlt):
```sh
CHECKMK=192.0.2.10
echo "onlyfrom: $CHECKMK" >> /usr/local/etc/checkmk.conf
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --restart
```
Mehrere Adressen durch Komma trennen: `onlyfrom: 192.0.2.10,2001:db8::10`. Ab 1.2.18 gehen auch Netze:
`onlyfrom: 192.0.2.0/28,2001:db8:1::/48`. Erlaubt sind nur IPv4- und IPv6-Adressen und -Netze; Hostnamen ignoriert
der Agent mit einer Warnung im Systemlog. Steht `onlyfrom` in der
Config, aber keine gültige Adresse (auch bei leerem Wert), lehnt er jede Verbindung ab. Abgelehnte Verbindungen stehen
im Systemlog als `Client 192.0.2.99 not allowed` (ab 1.2.18; vorher wurden sie nicht protokolliert).

:::warning
**Fehler bis 1.2.17:** Seit 1.2.11 nimmt der Agent IPv4 und IPv6 auf einem Socket an. Dort kommen IPv4-Clients als
`::ffff:192.0.2.10` an, und `onlyfrom: 192.0.2.10` lehnt deshalb jeden IPv4-Client ab: Checkmk bekommt keine Daten.
Behoben in 1.2.18. Bis zum Update hilft die Schreibweise `onlyfrom: ::ffff:192.0.2.10`; sie funktioniert auch ab
1.2.18 weiter.
:::

`onlyfrom` ersetzt nicht die Firewall-Regel: Port 6556 bleibt auf WAN geschlossen.

## Verschlüsselung
Ohne Verschlüsselung geht die Ausgabe im Klartext über das Netz. Mit `encrypt` verschlüsselt der Agent sie mit einem
gemeinsamen Passwort (AES-256-CBC, Schlüssel per PBKDF2-SHA256; das Format `03` der Checkmk-Agenten):
```sh
SECRET='ein-langes-zufaelliges-passwort'
echo "encrypt: $SECRET" >> /usr/local/etc/checkmk.conf
chmod 600 /usr/local/etc/checkmk.conf
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --restart
```
In Checkmk dasselbe Passwort für den Host hinterlegen: Setup › Agents › Agent access rules › „Symmetric encryption
(Linux, Windows)“. Danach die Änderungen aktivieren und den Host neu abfragen.

Das Passwort nicht mit `--encrypt` auf der Kommandozeile angeben: Es stünde dann in der Prozessliste.

Prüfen, ob der Agent verschlüsselt und das Passwort stimmt (auf der OPNsense; liest `encrypt` aus der Config):
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --checkoutput | head -3
```

## Ohne Checkmk: Zabbix
`--zabbix` gibt nur die lokalen Checks (die OPNsense-Services, nicht die Abschnitte) als JSON aus, zum Einlesen in
Zabbix per `system.run` oder Skript:
```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --zabbix
```
