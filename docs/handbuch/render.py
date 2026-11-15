#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# from trmm-web-relay (docs/handbuch/render.py), adapted for checkmk-opnsense-agent
"""Prepare the handbook articles for Outline (Git is the source, Outline only shows them).

  render.py list                         all articles in order: file, parent, title, Outline address, position
                                         under the parent (0-based, the index of move_document), Outline id,
                                         Outline id of the parent (the collection for a section)
  render.py render <file> [--allow-missing]
                                         the text for Outline: without header, links to other articles
                                         as Outline addresses; at the end a link to the next article (in the
                                         order of list, if it is published), the source file and Ko-fi
  render.py blocks <file> [<n>]          the sh/bash blocks of an article (numbered), or only block n, to run them
                                         word by word in a test container or on the test VM
  render.py publish [--since <commit>] [--dry-run]
                                         update the pages in Outline whose rendered text differs from the one at
                                         <commit> (without: all pages), _collection.md as the description of the
                                         collection; API key in OUTLINE_API_KEY, address in OUTLINE_URL (default
                                         https://docs.bashclub.org). Articles without outline_id are looked up
                                         by title under their parent and created if missing (collection: outline_id
                                         of _collection.md); all pages are put in the order of the handbook
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
REPO_URL = "https://code.bashclub.org/bashclub/checkmk-opnsense-agent/src/branch/main/docs/handbuch/"
KOFI_URL = "https://ko-fi.com/A0A1J73JR"
KOFI_NAME = "ko-fi.com/thorakel"
# the Ko-fi button (kofi-button.py) from the repository: readers load nothing from ko-fi.com; Outline cannot link an
# image, so the address follows below it
KOFI_BUTTON = "https://code.bashclub.org/bashclub/checkmk-opnsense-agent/raw/branch/main/docs/handbuch/kofi-block.png"
# Outline addresses found or created during publish, by absolute path (articles without outline/outline_id in the header)
URLS = {}
LINK = re.compile(r"\]\((?!https?://|#|mailto:)([^)#\s]+\.md)(#[^)\s]*)?\)")


def read(path):
    """header (dict) and text of an article"""
    with open(path, encoding="utf-8") as f:
        content = f.read()
    m = re.match(r"---\n(.*?)\n---\n", content, re.S)
    if not m:
        sys.exit(f"{path}: no header (--- title: … ---)")
    head = {}
    for line in m.group(1).splitlines():
        key, _, value = line.partition(":")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        head[key.strip()] = value
    if not head.get("title"):
        sys.exit(f"{path}: no title")
    return head, content[m.end():].lstrip("\n")


def articles():
    """(path, parent path or None) in the order of Outline"""
    result = []
    for section in sorted(d for d in os.listdir(ROOT) if re.match(r"\d+-", d) and os.path.isdir(os.path.join(ROOT, d))):
        index = os.path.join(ROOT, section, "_index.md")
        if not os.path.isfile(index):
            sys.exit(f"{section}: no _index.md")
        result.append((index, None))
        for name in sorted(n for n in os.listdir(os.path.join(ROOT, section)) if re.match(r"\d+-.*\.md$", n)):
            result.append((os.path.join(ROOT, section, name), index))
    return result


def rel(path):
    return os.path.relpath(path, ROOT)


BLOCK_START = re.compile(r"\s*([-*+] |\d+\. |\||#|:::|>|```|---$)")


def unwrap(text):
    """join the lines of a paragraph or list item wrapped in the source (Outline would keep the line breaks)"""
    out = []
    fence = False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fence = not fence
            out.append(line)
            continue
        prev = out[-1] if out else ""
        # a line that is bold as a whole (a message in the reference) stays a paragraph of its own
        if not fence and line.strip() and re.fullmatch(r"\*\*.*\*\*", prev.strip()) and not BLOCK_START.match(line):
            out.append("")
            out.append(line)
        elif (not fence and line.strip() and prev.strip() and not BLOCK_START.match(line)
                and not re.match(r"\s*(\||#|:::|```|---$)", prev)):
            out[-1] = prev.rstrip() + " " + line.strip()
        else:
            out.append(line)
    return "\n".join(out)


def render(path, allow_missing):
    head, text = read(path)
    if re.match(r"# ", text):
        sys.exit(f"{rel(path)}: the text must not start with a heading of the first level, Outline shows the title")
    missing = []

    def link(m):
        target = os.path.normpath(os.path.join(os.path.dirname(path), m.group(1)))
        if not os.path.isfile(target):
            sys.exit(f"{rel(path)}: link to a missing file {m.group(1)}")
        url = read(target)[0].get("outline", "") or URLS.get(target, ("", ""))[1]
        if not url:
            missing.append(rel(target))
            return "]()"
        # anchors in Outline: h-<heading as in the source>
        anchor = "#h-" + m.group(2)[1:] if m.group(2) else ""
        return f"]({url}{anchor})"

    text = LINK.sub(link, unwrap(text))
    if missing and not allow_missing:
        sys.exit(f"{rel(path)}: links to articles that are not published yet: {', '.join(sorted(set(missing)))}")
    # links whose target is not published yet: only the text stays
    text = re.sub(r"\[([^\]]*)\]\(\)", r"\1", text)
    # the next article in the order of the handbook (the next section after the last article of a section)
    order = [p for p, _ in articles()]
    following = ""
    if path in order and order.index(path) + 1 < len(order):
        nxt = order[order.index(path) + 1]
        head_next = read(nxt)[0]
        url_next = head_next.get("outline") or URLS.get(nxt, ("", ""))[1]
        if url_next:
            following = f"**Weiter:** [{head_next['title']}]({url_next})\n\n"
    # end of the page: the Ko-fi block, a table of one centered column (question and button in one picture, no alt
    # text, Outline would show it as a caption; below it the link) between empty paragraphs (\\ in Outline), the next
    # article, the note on the source
    kofi = f"\\\n\n| ![]({KOFI_BUTTON}) |\n|:---:|\n| [{KOFI_NAME}]({KOFI_URL}) |\n\n\\\n\n"
    if os.path.basename(path) == "_collection.md":
        kofi = ""   # the start page has the block in its contact section
    note = (f"---\n\n*Quelle dieser Seite: [{rel(path)}]({REPO_URL}{rel(path)}) im Repository von checkmk-opnsense-agent. "
            "Änderungen bitte dort, diese Seite wird daraus erzeugt.*\n")
    return text.rstrip("\n") + "\n\n" + kofi + following + note


def blocks(path):
    """the sh/bash code blocks of an article"""
    return re.findall(r"^\s*```(?:sh|bash)\n(.*?)^\s*```", read(path)[1], re.S | re.M)


NOTE = re.compile(r"\n---\n\n\*Quelle dieser Seite: .*\Z", re.S)


def old_renders(since):
    """the rendered text of every article at commit since, by path relative to ROOT (missing articles are absent)"""
    result = {}
    top = subprocess.run(["git", "-C", ROOT, "rev-parse", "--show-toplevel"], capture_output=True, text=True,
                         check=True).stdout.strip()
    prefix = os.path.relpath(ROOT, top)
    with tempfile.TemporaryDirectory() as tmp:
        archive = subprocess.run(["git", "-C", top, "archive", since, prefix], capture_output=True)
        if archive.returncode:
            sys.exit(f"git archive {since}: {archive.stderr.decode().strip()}")
        subprocess.run(["tar", "-x", "-C", tmp], input=archive.stdout, check=True)
        old_root = os.path.join(tmp, prefix)
        for path in [p for p, _ in articles()] + [os.path.join(ROOT, "_collection.md")]:
            old = os.path.join(old_root, rel(path))
            if os.path.isfile(old):
                out = subprocess.run([sys.executable, os.path.join(old_root, "render.py"), "render", old,
                                      "--allow-missing"], capture_output=True, text=True)
                if out.returncode == 0:
                    result[rel(path)] = (read(old)[0].get("title"), out.stdout)
    return result


def api(method, data):
    url = os.environ.get("OUTLINE_URL", "https://docs.bashclub.org").rstrip("/") + "/api/" + method
    request = urllib.request.Request(url, data=json.dumps(data).encode(), method="POST", headers={
        "Authorization": "Bearer " + os.environ["OUTLINE_API_KEY"], "Content-Type": "application/json",
        "Accept": "application/json", "User-Agent": "checkmk-opnsense-agent-handbuch"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def ensure_pages(dry_run):
    """outline id and address of every article: from the header, found by title under its parent, or created;
    then all pages are moved into the order of the handbook. Returns the paths of created pages."""
    base = os.environ.get("OUTLINE_URL", "https://docs.bashclub.org").rstrip("/")
    collection_id = read(os.path.join(ROOT, "_collection.md"))[0].get("outline_id")
    if not collection_id:
        sys.exit("_collection.md: no outline_id (id of the collection)")
    if dry_run and not os.environ.get("OUTLINE_API_KEY"):
        return []
    tree = api("collections.documents", {"id": collection_id})["data"]
    created = []
    position = {}
    for path, parent in articles():
        head = read(path)[0]
        if head.get("outline_id"):
            URLS[path] = (head["outline_id"], head.get("outline", ""))
        else:
            siblings = tree if not parent else next((n.get("children", []) for n in walk(tree)
                                                     if n["id"] == URLS.get(parent, ("",))[0]), [])
            node = next((n for n in siblings if n["title"] == head["title"]), None)
            if node:
                URLS[path] = (node["id"], base + node["url"])
            elif dry_run:
                print(f"would create: {rel(path)} ({head['title']})")
                continue
            else:
                data = {"collectionId": collection_id, "title": head["title"], "text": "", "publish": True}
                if parent:
                    data["parentDocumentId"] = URLS[parent][0]
                doc = api("documents.create", data)["data"]
                URLS[path] = (doc["id"], base + doc["url"])
                created.append(path)
                print(f"create: {rel(path)} ({head['title']})")
        # the order of the handbook (Outline puts new pages anywhere)
        key = parent or ""
        position[key] = position.get(key, -1) + 1
        if not dry_run and path in URLS:
            move = {"id": URLS[path][0], "index": position[key]}
            move.update({"parentDocumentId": URLS[parent][0]} if parent else {"collectionId": collection_id})
            api("documents.move", move)
    return created


def walk(nodes):
    for node in nodes:
        yield node
        yield from walk(node.get("children", []))


def publish(since, dry_run):
    if not dry_run and not os.environ.get("OUTLINE_API_KEY"):
        sys.exit("OUTLINE_API_KEY is not set")
    created = ensure_pages(dry_run)
    old = old_renders(since) if since and not created else {}
    collection = os.path.join(ROOT, "_collection.md")
    changed = 0
    for path in [p for p, _ in articles()] + [collection]:
        head = read(path)[0]
        text = render(path, dry_run)
        if old.get(rel(path)) == (head["title"], text):
            continue
        page_id = head.get("outline_id") or URLS.get(path, ("",))[0]
        if not page_id:
            print(f"{'would create and update' if dry_run else 'missing'}: {rel(path)}")
            continue
        changed += 1
        print(f"{'would update' if dry_run else 'update'}: {rel(path)} ({head['title']})")
        if dry_run:
            continue
        if path == collection:
            try:
                api("collections.update", {"id": page_id, "name": head["title"],
                                           "description": NOTE.sub("\n", text)})
            except urllib.error.HTTPError as error:
                # "Kann bearbeiten" reicht für die Seiten, die Startseite (Beschreibung) braucht "Verwalten"
                if error.code != 403:
                    raise
                changed -= 1
                print(f"skip: {rel(path)} (403: no manage right on the collection, update the start page by hand)")
        else:
            api("documents.update", {"id": page_id, "title": head["title"], "text": text})
    print(f"{changed} page(s) {'to update' if dry_run else 'updated'}")


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "list":
        collection = read(os.path.join(ROOT, "_collection.md"))[0].get("outline_id") or "-"
        position, sections = {}, 0
        for path, parent in articles():
            head = read(path)[0]
            if parent:
                position[parent] = position.get(parent, -1) + 1
                index, parent_id = position[parent], read(parent)[0].get("outline_id") or "-"
            else:
                index, parent_id, sections = sections, collection, sections + 1
            print("\t".join([rel(path), rel(parent) if parent else "-", head["title"], head.get("outline") or "-",
                             str(index), head.get("outline_id") or "-", parent_id]))
    elif len(sys.argv) >= 3 and sys.argv[1] == "render":
        sys.stdout.write(render(os.path.abspath(sys.argv[2]), "--allow-missing" in sys.argv[3:]))
    elif len(sys.argv) >= 3 and sys.argv[1] == "blocks":
        found = blocks(os.path.abspath(sys.argv[2]))
        if len(sys.argv) >= 4:
            sys.stdout.write(found[int(sys.argv[3]) - 1])
        else:
            for n, block in enumerate(found, 1):
                print(f"### {n}\n{block}")
    elif len(sys.argv) >= 2 and sys.argv[1] == "publish":
        args = sys.argv[2:]
        since = args[args.index("--since") + 1] if "--since" in args else None
        publish(since, "--dry-run" in args)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
