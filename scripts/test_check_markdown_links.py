# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Tests for the Markdown link and anchor checker."""

from __future__ import annotations

import unittest

from check_markdown_links import anchors_in, github_slug, targets_in


class GithubSlugTests(unittest.TestCase):
    def test_lowercases_drops_punctuation_and_joins_words_with_hyphens(self) -> None:
        self.assertEqual(
            github_slug("Native proxy and host loopback"),
            "native-proxy-and-host-loopback",
        )
        self.assertEqual(github_slug("3.2 Clock & time"), "32-clock--time")

    def test_keeps_underscores_and_code_text(self) -> None:
        self.assertEqual(github_slug("The `nvx_tools` module"), "the-nvx_tools-module")


class AnchorTests(unittest.TestCase):
    def test_duplicate_headings_get_numbered_suffixes(self) -> None:
        anchors = anchors_in("# Setup\n\n## Setup\n\n## Setup\n")
        self.assertEqual(anchors, {"setup", "setup-1", "setup-2"})

    def test_headings_inside_fences_do_not_count(self) -> None:
        anchors = anchors_in("```\n# Not a heading\n```\n\n# Real\n")
        self.assertEqual(anchors, {"real"})


class TargetTests(unittest.TestCase):
    def test_links_in_code_are_ignored(self) -> None:
        text = "`[inline](missing.md)`\n\n```\n[fenced](missing.md)\n```\n\n[live](real.md)\n"
        self.assertEqual(targets_in(text), [(7, "real.md")])

    def test_images_and_html_targets_are_found(self) -> None:
        text = '![diagram](img/a.png)\n<a href="other.md#x">x</a>\n'
        self.assertEqual(targets_in(text), [(1, "img/a.png"), (2, "other.md#x")])


if __name__ == "__main__":
    unittest.main()
