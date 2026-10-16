#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Check relative links, images, and anchors in tracked Markdown files.

Every relative link or image target must exist in the working tree, and every
anchor must match a heading slug in the target file, using GitHub's rules.
Inline links, reference-style definitions, and HTML ``href`` and ``src``
attributes are checked. Fenced code blocks and code spans are ignored. Files
under ``openvmm/`` are vendored and skipped.
"""

from __future__ import annotations

import html
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parent.parent
SKIPPED_PREFIXES = ("openvmm/",)

FENCE_OPEN = re.compile(r"^[ \t]*(?P<run>`{3,}|~{3,})(?P<info>.*)$")
FENCE_CLOSE = re.compile(r"^[ \t]*(?P<run>`{3,}|~{3,})[ \t]*$")
HEADING = re.compile(r"^ {0,3}#{1,6}[ \t]+(?P<text>.+?)[ \t]*#*[ \t]*$")
SETEXT_UNDERLINE = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
# A code span opens and closes with the same run length and may span lines.
CODE_SPAN = re.compile(
    r"(?<!`)(?P<run>`+)(?!`)(?P<body>(?:(?!\n[ \t]*\n).)*?)(?<!`)(?P=run)(?!`)", re.S
)
INLINE_LINK = re.compile(
    r"(?<!\\)!?\[(?P<label>(?:[^\[\]]|\[[^\]]*\])*)\]"
    r"\([ \t\n]*<?(?P<target>[^)\s>]+)>?(?:[ \t\n]+\"[^\"]*\")?[ \t\n]*\)"
)
REFERENCE_DEFINITION = re.compile(
    r"^ {0,3}\[(?P<label>[^\]\n]+)\]:[ \t]*<?(?P<target>[^\s>]+)>?", re.M
)
HTML_TARGET = re.compile(r"""\b(?:href|src)\s*=\s*["'](?P<target>[^"']+)["']""")
HTML_ID = re.compile(r"""\b(?:id|name)\s*=\s*["'](?P<id>[^"']+)["']""")
HTML_TAG = re.compile(r"<[^>]+>")
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def _blank(text: str) -> str:
    """Return ``text`` with everything but its newlines replaced by spaces."""
    return re.sub(r"[^\n]", " ", text)


def _mask_fences(markdown: str) -> str:
    """Blank fenced code blocks, keeping line numbers.

    A fence closes only on its own character, with at least its opening length.
    """
    kept: list[str] = []
    opening: tuple[str, int] | None = None
    for line in markdown.split("\n"):
        if opening is None:
            match = FENCE_OPEN.match(line)
            if match and not (match["run"][0] == "`" and "`" in match["info"]):
                opening = (match["run"][0], len(match["run"]))
                kept.append("")
                continue
            kept.append(line)
            continue
        close = FENCE_CLOSE.match(line)
        if close and close["run"][0] == opening[0] and len(close["run"]) >= opening[1]:
            opening = None
        kept.append("")
    return "\n".join(kept)


def _mask_code_spans(markdown: str) -> str:
    return CODE_SPAN.sub(lambda match: _blank(match.group(0)), markdown)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def github_slug(heading: str) -> str:
    """Return the anchor GitHub generates for a heading's rendered text."""
    code: list[str] = []

    def stash(match: re.Match[str]) -> str:
        code.append(match["body"])
        return f"\x00{len(code) - 1}\x00"

    text = CODE_SPAN.sub(stash, heading)
    text = INLINE_LINK.sub(lambda match: match["label"], text)
    text = HTML_TAG.sub("", text)
    text = html.unescape(text)
    text = text.replace("*", "")
    text = re.sub(r"(?<![A-Za-z0-9])_+|_+(?![A-Za-z0-9])", "", text)
    text = re.sub(r"\x00(\d+)\x00", lambda match: code[int(match.group(1))], text)
    kept = [
        "-" if char == " " else char
        for char in text.strip().lower()
        if char in " -_" or char.isalnum()
    ]
    return "".join(kept)


def _headings(markdown: str) -> list[str]:
    """Return the rendered text of each ATX and Setext heading, in order."""
    masked = _mask_code_spans(_mask_fences(markdown)).split("\n")
    raw = markdown.split("\n")
    headings: list[str] = []
    for index, line in enumerate(masked):
        atx = HEADING.match(line)
        if atx:
            headings.append(HEADING.match(raw[index])["text"])  # type: ignore[index]
            continue
        if index == 0 or not SETEXT_UNDERLINE.match(line):
            continue
        if not masked[index - 1].strip():
            continue
        start = index
        while (
            start > 0
            and masked[start - 1].strip()
            and not HEADING.match(masked[start - 1])
        ):
            start -= 1
        headings.append(" ".join(part.strip() for part in raw[start:index]))
    return headings


def anchors_in(markdown: str) -> set[str]:
    """Return every anchor a document defines, with GitHub's duplicate suffixes."""
    anchors: set[str] = set()
    for heading in _headings(markdown):
        slug = github_slug(heading)
        candidate = slug
        suffix = 1
        while candidate in anchors:
            candidate = f"{slug}-{suffix}"
            suffix += 1
        anchors.add(candidate)
    anchors.update(HTML_ID.findall(_mask_code_spans(_mask_fences(markdown))))
    return anchors


def _parse_destination(text: str, start: int) -> str | None:
    """Return the destination of an inline link whose ``](`` ends before ``start``.

    Handles angle-bracketed destinations, balanced parentheses, and an optional
    quoted or parenthesized title. Returns None when the link is not closed.
    """
    index = start
    size = len(text)
    while index < size and text[index] in " \t\n":
        index += 1
    if index < size and text[index] == "<":
        close = text.find(">", index + 1)
        if close == -1:
            return None
        destination = text[index + 1 : close]
        index = close + 1
    else:
        begin = index
        depth = 0
        while index < size:
            char = text[index]
            if char == "\\" and index + 1 < size:
                index += 2
                continue
            if char in " \t\n":
                break
            if char == "(":
                depth += 1
            elif char == ")":
                if depth == 0:
                    break
                depth -= 1
            index += 1
        destination = text[begin:index]
    after = index
    while after < size and text[after] in " \t\n":
        after += 1
    if after < size and text[after] in "\"'(":
        closer = {'"': '"', "'": "'", "(": ")"}[text[after]]
        end = text.find(closer, after + 1)
        if end == -1:
            return None
        after = end + 1
        while after < size and text[after] in " \t\n":
            after += 1
    if after < size and text[after] == ")":
        return destination
    return None


def _opening_bracket(masked: str, close: int) -> int | None:
    """Return the offset of the ``[`` matching the ``]`` at ``close``, if any."""
    depth = 0
    for index in range(close, -1, -1):
        if index and masked[index - 1] == "\\":
            continue
        char = masked[index]
        if char == "]":
            depth += 1
        elif char == "[":
            depth -= 1
            if depth == 0:
                return index
    return None


def _inline_targets(masked: str) -> list[tuple[int, str]]:
    """Return (line, destination) for each inline link, including images nested in labels."""
    found: list[tuple[int, str]] = []
    for index in range(len(masked) - 1):
        if masked[index : index + 2] != "](":
            continue
        if index and masked[index - 1] == "\\":
            continue
        destination = _parse_destination(masked, index + 2)
        opener = _opening_bracket(masked, index)
        if destination is None or opener is None:
            continue
        found.append((_line_of(masked, opener), destination))
    return found


def targets_in(markdown: str) -> list[tuple[int, str]]:
    """Return (line number, target) for each link, definition, and HTML target."""
    masked = _mask_code_spans(_mask_fences(markdown))
    found: list[tuple[int, str]] = []
    found.extend(_inline_targets(masked))
    for pattern in (REFERENCE_DEFINITION, HTML_TARGET):
        for match in pattern.finditer(masked):
            found.append((_line_of(masked, match.start()), match["target"]))
    return sorted(found)


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
    path_part = path_part.partition("?")[0]
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
