# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Tests for the Markdown link and anchor checker."""

from __future__ import annotations

import unittest

from check_markdown_links import (
    REPO_ROOT,
    anchors_in,
    check_target,
    github_slug,
    targets_in,
)


class GithubSlugTests(unittest.TestCase):
    def test_lowercases_drops_punctuation_and_joins_words_with_hyphens(self) -> None:
        self.assertEqual(
            github_slug("Native proxy and host loopback"),
            "native-proxy-and-host-loopback",
        )
        self.assertEqual(github_slug("3.2 Clock & time"), "32-clock--time")

    def test_keeps_underscores_inside_words_and_in_code(self) -> None:
        self.assertEqual(github_slug("The `nvx_tools` module"), "the-nvx_tools-module")

    def test_drops_emphasis_markers_from_rendered_text(self) -> None:
        self.assertEqual(github_slug("_Setup_"), "setup")
        self.assertEqual(github_slug("**Bold** and *italic*"), "bold-and-italic")


class AnchorTests(unittest.TestCase):
    def test_duplicate_headings_get_numbered_suffixes(self) -> None:
        anchors = anchors_in("# Setup\n\n## Setup\n\n## Setup\n")
        self.assertEqual(anchors, {"setup", "setup-1", "setup-2"})

    def test_generated_suffix_skips_a_slug_already_taken(self) -> None:
        self.assertEqual(
            anchors_in("# Setup\n# Setup\n# Setup-1\n"),
            {"setup", "setup-1", "setup-1-1"},
        )
        self.assertEqual(
            anchors_in("# Setup\n# Setup-1\n# Setup\n"),
            {"setup", "setup-1", "setup-2"},
        )

    def test_headings_inside_fences_do_not_count(self) -> None:
        anchors = anchors_in("```\n# Not a heading\n```\n\n# Real\n")
        self.assertEqual(anchors, {"real"})

    def test_setext_headings_provide_anchors(self) -> None:
        self.assertEqual(anchors_in("Setup\n=====\n\nMore\n---\n"), {"setup", "more"})

    def test_setext_and_atx_duplicates_share_one_sequence(self) -> None:
        self.assertEqual(anchors_in("# Setup\n\nSetup\n-----\n"), {"setup", "setup-1"})

    def test_formatted_headings_use_their_rendered_text(self) -> None:
        self.assertEqual(
            anchors_in("## _Setup_\n\n## `nvx_tools` module\n"),
            {"setup", "nvx_tools-module"},
        )


class TargetTests(unittest.TestCase):
    def test_links_in_code_are_ignored(self) -> None:
        text = "`[inline](missing.md)`\n\n```\n[fenced](missing.md)\n```\n\n[live](real.md)\n"
        self.assertEqual(targets_in(text), [(7, "real.md")])

    def test_images_and_html_targets_are_found(self) -> None:
        text = '![diagram](img/a.png)\n<a href="other.md#x">x</a>\n'
        self.assertEqual(targets_in(text), [(1, "img/a.png"), (2, "other.md#x")])

    def test_fence_closes_only_on_the_same_character_and_length(self) -> None:
        text = "````\n```\n[example](missing.md)\n```\n````\n[real](real.md)\n"
        self.assertEqual(targets_in(text), [(6, "real.md")])

    def test_multi_backtick_code_spans_hide_links(self) -> None:
        text = "`` `[example](missing.md)` ``\n\n[live](real.md)\n"
        self.assertEqual(targets_in(text), [(3, "real.md")])

    def test_code_spans_do_not_cross_paragraphs(self) -> None:
        text = "`unmatched\n\n[real](real.md)\n\n`other`\n"
        self.assertEqual(targets_in(text), [(3, "real.md")])

    def test_multiline_link_labels_are_found(self) -> None:
        text = "[draft or ready for\nreview](#draft-or-ready)\n"
        self.assertEqual(targets_in(text), [(1, "#draft-or-ready")])

    def test_reference_definitions_are_checked(self) -> None:
        text = "See [guide][g], [Guide][], and [g].\n\n[g]: missing.md\n[G]: other.md\n"
        self.assertEqual(
            sorted(targets_in(text)),
            [(3, "missing.md"), (4, "other.md")],
        )

    def test_undefined_reference_labels_are_not_links(self) -> None:
        self.assertEqual(targets_in("[text][nope] and [other]\n"), [])


if __name__ == "__main__":
    unittest.main()


class ParserRegressionTests(unittest.TestCase):
    def test_parentheses_balance_inside_a_destination(self) -> None:
        self.assertEqual(targets_in("[guide](guide(v2).md)\n"), [(1, "guide(v2).md")])

    def test_titles_are_not_part_of_the_destination(self) -> None:
        self.assertEqual(targets_in("[g](guide.md 'Guide')\n"), [(1, "guide.md")])
        self.assertEqual(targets_in('[g](guide.md "Guide")\n'), [(1, "guide.md")])

    def test_angle_bracketed_destinations_may_contain_spaces(self) -> None:
        self.assertEqual(
            targets_in("[g](<dir with space/g.md>)\n"), [(1, "dir with space/g.md")]
        )

    def test_images_nested_in_link_labels_are_checked(self) -> None:
        found = targets_in("[![diagram](missing.png)](README.md)\n")
        self.assertEqual(sorted(found), [(1, "README.md"), (1, "missing.png")])

    def test_fences_indented_inside_list_items_are_recognized(self) -> None:
        text = "- item\n\n    ```\n    [example](missing.md)\n\n    ```\n\n[live](real.md)\n"
        self.assertEqual(targets_in(text), [(8, "real.md")])

    def test_query_strings_are_not_part_of_the_path(self) -> None:
        self.assertIsNone(check_target(REPO_ROOT / "README.md", 1, "README.md?plain=1"))

    def test_html_entities_in_headings_are_decoded(self) -> None:
        self.assertEqual(anchors_in("# Build &amp; run\n"), {"build--run"})

    def test_entities_inside_code_spans_stay_literal(self) -> None:
        self.assertEqual(anchors_in("# `&amp;`\n"), {"amp"})


class EscapeRegressionTests(unittest.TestCase):
    def test_punctuation_escapes_in_inline_and_reference_destinations_are_decoded(
        self,
    ) -> None:
        text = "[guide](guide\\(v2\\).md)\n\n[g]: guide\\(v2\\).md\n"
        self.assertEqual(
            sorted(targets_in(text)),
            [(1, "guide(v2).md"), (3, "guide(v2).md")],
        )

    def test_html_attribute_backslashes_are_not_decoded(self) -> None:
        self.assertEqual(targets_in('<a href="a\\(b.md">x</a>\n'), [(1, "a\\(b.md")])
