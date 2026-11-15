# Handbuch checkmk-opnsense-agent: Regeln für Autoren

Das Handbuch entsteht hier im Repo und soll nach Outline (docs.bashclub.org) veröffentlicht werden, wie die
Handbücher von bashclub-zsync und trmm-web-relay. **Noch nicht veröffentlicht:** Die Collection, `render.py`, `ci.sh`
und der Workflow `.forgejo/workflows/handbuch.yml` kommen mit dem ersten Release, das das Handbuch enthält. Die Vorlage
dafür ist trmm-web-relay: Jeder Push auf `main` veröffentlicht die geänderten Seiten. Weil `main` hier nur Releases
bekommt, zeigt Outline immer den Stand des aktuellen Releases; `testing` ändert das Handbuch, ohne es zu
veröffentlichen.

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
