# Handbuch checkmk-opnsense-agent: Regeln für Autoren

Das Handbuch entsteht hier im Repo und wird nach Outline veröffentlicht, wie die Handbücher von bashclub-zsync und
trmm-web-relay:
- öffentlich, ohne Login: https://docs.bashclub.org/s/checkmk-opnsense-agent
- mit Login (für Autoren): https://docs.bashclub.org/collection/opnsense-agent-for-checkmk-uN5D2q804g

Jeder Push auf `main` veröffentlicht die geänderten Seiten (`.forgejo/workflows/handbuch.yml`, `ci.sh`,
`render.py publish`, Secret `OUTLINE_API_KEY`). Weil `main` nur Releases bekommt, zeigt Outline immer den Stand des
aktuellen Releases; `testing` ändert das Handbuch, ohne es zu veröffentlichen. `tests/handbuch.sh` prüft das Handbuch
in jeder CI: jede Option und jeder Check steht in der Referenz, jeder Artikel lässt sich aufbereiten.

**Git ist die Quelle.** Änderungen direkt in Outline werden beim nächsten Veröffentlichen überschrieben.

## Aufbau
- Ein Ordner je Bereich (`01-einrichtung`, `02-referenz`, …), die Nummer bestimmt die Reihenfolge.
- `_index.md` im Ordner ist die Seite des Bereichs, die Artikel des Ordners hängen darunter.
- Artikel heißen `NN-name.md`, die Nummer bestimmt die Reihenfolge im Bereich.
- `_collection.md` ist die Startseite des Handbuchs mit der Liste der Bereiche.

Jede Datei beginnt mit einem Kopf:
```
---
title: Installation
audience: Admin
outline:
---
```
- `title`: Titel in Outline. Der Text beginnt ohne Überschrift erster Ebene (`#`).
- `audience`: `Anwender`, `Admin` oder `Anwender, Admin`.
- `outline`, `outline_id`: Adresse und ID der Seite in Outline, beim ersten Veröffentlichen eingetragen.

## Versionen
Das Handbuch beschreibt den Agent ab 1.2.17. Funktionen und Fixes ab 1.2.17 nennen ihre Version („ab 1.2.18“).
Geändertes Verhalten steht in einer Hinweisbox mit altem und neuem Verhalten:
```
:::info
**Geändert in 1.2.18:** Bis 1.2.17 … Ab 1.2.18 …
:::
```

## Befehle
- Copy & Paste-fest: Befehle laufen so, wie sie dastehen, auf der OPNsense-Shell (`sh` bzw. `csh` als root). Wo der
  Admin einen Wert wählen muss, steht er als Variable in der ersten Zeile des Blocks.
- Codeblöcke mit Sprache, ein Befehl pro Zeile, Ausgaben getrennt davon.
- Befehle werden vor dem Veröffentlichen auf der Test-VM ausgeführt.

## Sprache und Stil
- Deutsch zuerst; eine englische Fassung folgt, wenn die deutschen Artikel stehen.
- Kurze Sätze, Programme, Optionen, Dateien und Service-Namen in `Code`.
- Auf andere Artikel relativ verlinken: `[Konfiguration](../02-referenz/01-konfiguration.md)`.

## Pflege
- Ein neuer Check, eine neue Option oder ein geänderter Zustand ändert die Referenz
  ([Services](02-referenz/02-services.md), [Konfiguration](02-referenz/01-konfiguration.md)) im selben Commit.
- Ein behobener Fehler aus [Bekannte Probleme](03-fehlerbehebung/02-bekannte-probleme.md) wird dort entfernt und,
  wenn sich der Betrieb ändert, mit Versionsvermerk beschrieben.

## Veröffentlichen
`render.py publish` legt Artikel ohne `outline_id` selbst an (gesucht wird zuerst über den Titel unter ihrem
Bereich), bringt alle Seiten in die Reihenfolge des Handbuchs und aktualisiert die geänderten. `outline` und
`outline_id` im Kopf sind danach optional, machen aber Umbenennungen sicher: Ohne ID legt ein neuer Titel eine neue
Seite an, die alte bleibt stehen. Von Hand:
```sh
docs/handbuch/render.py list
docs/handbuch/render.py render docs/handbuch/01-einrichtung/01-installation.md --allow-missing
docs/handbuch/render.py publish --dry-run
```
Alle Seiten neu veröffentlichen: Workflow `handbuch` von Hand starten (workflow_dispatch).
