#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Check relative links, images, and anchors in tracked Markdown files.

Every relative link or image target must exist in the working tree, and every
anchor must match a heading slug, using GitHub's rules, in the target file. Code
spans and fenced code blocks are ignored. Files under ``openvmm/`` are vendored
and skipped.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parent.parent
SKIPPED_PREFIXES = ("openvmm/",)

FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(?P<text>.+?)\s*#*\s*$")
INLINE_CODE = re.compile(r"`[^`]*`")
LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?(?P<target>[^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
HTML_TARGET = re.compile(r"""\b(?:href|src)\s*=\s*["'](?P<target>[^"']+)["']""")
HTML_ID = re.compile(r"""\b(?:id|name)\s*=\s*["'](?P<id>[^"']+)["']""")
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def github_slug(heading: str) -> str:
    """Return the anchor GitHub generates for a heading's text."""
    text = INLINE_CODE.sub(lambda match: match.group(0).strip("`"), heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    kept = [
        "-" if char == " " else char
        for char in text.strip().lower()
        if char in " -_" or char.isalnum()
    ]
    return "".join(kept)


def anchors_in(markdown: str) -> set[str]:
    """Return every anchor a Markdown document defines, including duplicate suffixes."""
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    in_fence = False
    for line in markdown.splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        heading = HEADING.match(line)
        if heading:
            slug = github_slug(heading.group("text"))
            count = seen.get(slug, 0)
            seen[slug] = count + 1
            anchors.add(slug if count == 0 else f"{slug}-{count}")
        anchors.update(HTML_ID.findall(line))
    return anchors


def targets_in(markdown: str) -> list[tuple[int, str]]:
    """Return (line number, target) for each link outside code."""
    found: list[tuple[int, str]] = []
    in_fence = False
    for number, line in enumerate(markdown.splitlines(), start=1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        prose = INLINE_CODE.sub("", line)
        for match in LINK.finditer(prose):
            found.append((number, match.group("target")))
        for match in HTML_TARGET.finditer(prose):
            found.append((number, match.group("target")))
    return found


def _in_skipped_tree(path: Path) -> bool:
    """Return whether a path lies in a vendored tree this check does not cover."""
    try:
        relative = path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return False
    return relative.startswith(SKIPPED_PREFIXES)


def check_target(source: Path, number: int, target: str) -> str | None:
    """Return a problem description for one link, or None if it resolves."""
    if target.startswith("//") or SCHEME.match(target):
        return None
    path_part, _, fragment = target.partition("#")
    if path_part:
        base = REPO_ROOT if path_part.startswith("/") else source.parent
        destination = base / unquote(path_part.lstrip("/"))
        if _in_skipped_tree(destination):
            return None
        if not destination.exists():
            return f"{source}:{number}: missing target '{target}'"
    else:
        destination = source
    if fragment and destination.is_file() and destination.suffix == ".md":
        markdown = destination.read_text(encoding="utf-8")
        if unquote(fragment) not in anchors_in(markdown):
            return f"{source}:{number}: no heading for anchor '#{fragment}' in {destination.name}"
    return None


def tracked_markdown() -> list[Path]:
    """Return the tracked Markdown files this check covers."""
    listing = subprocess.run(
        ["git", "ls-files", "--", "*.md"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    return [
        REPO_ROOT / name for name in listing if not name.startswith(SKIPPED_PREFIXES)
    ]


def main() -> int:
    problems: list[str] = []
    for source in tracked_markdown():
        text = source.read_text(encoding="utf-8")
        for number, target in targets_in(text):
            problem = check_target(source, number, target)
            if problem:
                problems.append(problem)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f"{len(problems)} broken Markdown link(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
