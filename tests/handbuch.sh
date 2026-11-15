#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# shellcheck disable=SC2016 # eval mit einfachen Anführungszeichen: Variablen erst beim Auswerten
# Handbuch (docs/handbuch): Referenz vollständig, Artikel lassen sich für Outline aufbereiten.
# Ohne Netz, ohne OPNsense. Aufruf im Wurzelverzeichnis des Repos: tests/handbuch.sh
repo=$(cd "$(dirname "$0")/.." && pwd)
docs=$repo/docs/handbuch
agent=$repo/opnsense_checkmk_agent.py
conf=$docs/02-referenz/01-konfiguration.md
services=$docs/02-referenz/02-services.md
count=0 failed=0
check() { ((count++)); if "${@:2}"; then echo "ok   $1"; else echo "FAIL $1"; ((failed++)); fi; }

# jede Option der Konfigurationsdatei hat eine Zeile in der Tabelle
opts=$(grep -oE '^CONFIG_OPTIONS = \(.*\)' "$agent" | grep -oE '"[a-z_]+"' | tr -d '"')
for o in $opts; do
	check "Option $o in der Konfiguration" grep -q "^| \`$o\` |" "$conf"
done

# jede Option der Kommandozeile steht in der Konfiguration
cli=$(grep -oE '_parser\.add_argument\("(-h",")?--[a-z_-]+' "$agent" | grep -oE -- '--[a-z_-]+')
for o in $cli; do
	check "Kommandozeile $o" grep -qE -- "\`$o( |\`)" "$conf"
done

# jeder Check (skipcheck-Name) steht in der Tabelle der Services
checks=$(grep -oE '^    def (check|checklocal)_[a-z0-9]+\(self' "$agent" | sed -E 's/.*_([a-z0-9]+)\(self/\1/' | sort -u)
for c in $checks; do
	check "Check $c in den Services" grep -qE "^\| ([^|]*, )?\`$c\`" "$services"
done

# alle Artikel: Kopf, keine Überschrift erster Ebene, Links auf vorhandene Dateien
while IFS=$'\t' read -r file _; do
	check "aufbereitbar: $file" eval '"$docs/render.py" render "$docs/$file" --allow-missing > /dev/null'
done < <("$docs/render.py" list)
check "aufbereitbar: _collection.md" eval '"$docs/render.py" render "$docs/_collection.md" --allow-missing > /dev/null'

# kein Text hinter einem schließenden ``` (Markdown nähme ihn als Sprache des Blocks)
check "kein Text hinter \`\`\`" eval '! grep -rnE "^\s*\`\`\` +[^ ]" "$docs"'

# nichts Internes: nur Beispieldomains und öffentliche Adressen
check "nur Beispieldomains" eval '! grep -rnoE "[a-z0-9-]+\.(de|com|net|org|io|cloud)\b" "$docs" --include=*.md | grep -vE "example\.(com|org)|bashclub\.org|spille-it\.de|youtube\.com|github\.com|ko-fi\.com|checkmk\.com|cymru\.com"'

echo "$((count - failed))/$count bestanden"
[ $failed -eq 0 ]
