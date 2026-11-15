#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# CI: Handbuch prüfen und nach Outline veröffentlichen, im Quellstand aufgerufen
#   docs/handbuch/ci.sh pull_request <basis>   nur zeigen, was nach dem Merge veröffentlicht würde
#   docs/handbuch/ci.sh push <vorher>          Seiten, die sich seit <vorher> geändert haben, ohne gültiges <vorher> alle
#   docs/handbuch/ci.sh all                    alle Seiten (von Hand gestartet)
# main bekommt nur Releases: Outline zeigt immer das Handbuch des aktuellen Releases.
# Secret OUTLINE_API_KEY, optional OUTLINE_URL (Default https://docs.bashclub.org)
set -euo pipefail
mode=$1 ref=${2:-}
tests/handbuch.sh
since=
if [[ -n $ref ]] && git cat-file -e "$ref^{commit}" 2>/dev/null; then since=$ref; fi
if [[ $mode == pull_request ]]; then
    docs/handbuch/render.py publish ${since:+--since "$(git merge-base HEAD "$since")"} --dry-run
    exit 0
fi
[[ $mode == all ]] && since=
# die Job-Container kennen nur code.bashclub.org (fester Eintrag), Outline liegt hinter demselben Proxy
host=$(python3 -c 'import os, urllib.parse; print(urllib.parse.urlparse(os.environ.get("OUTLINE_URL") or "https://docs.bashclub.org").hostname)')
if ! getent hosts "$host" > /dev/null; then
    addr=$(getent hosts code.bashclub.org | awk '{ print $1; exit }')
    if [[ -n $addr && -w /etc/hosts ]]; then
        echo "$addr $host" >> /etc/hosts
        echo "$host nicht auflösbar, nehme $addr (Adresse von code.bashclub.org)"
    fi
fi
docs/handbuch/render.py publish ${since:+--since "$since"}
