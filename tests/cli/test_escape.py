"""Spec 6.13 escaping per sink (the escape functions of claim C12; Task 9
feeds the same values through every output format)."""
from __future__ import annotations

from spellwarden_cli.escape import code_span, codequality, log_lines, markdown, message, terminal

HOSTILE = "a\tb\nc\x1b[31m|`x`<script>@channel‮Z\x85"


def test_terminal_escapes_controls_bidi_and_line_breaks():
    assert terminal(HOSTILE) == "a\\tb\\nc\\x1b[31m|`x`<script>@channel\\u{202E}Z\\x85"
    assert terminal("one\ntwo\tthree", single_line=False) == "one\ntwo\tthree"
    assert terminal("\x7f​﻿\U000e0041") == "\\x7f\\u{200B}\\u{FEFF}\\u{E0041}"
    assert terminal("plain ünïcode ✓") == "plain ünïcode ✓"


def test_markdown_escapes_punctuation_and_html():
    assert markdown(HOSTILE) == ("a\\\\tb\\\\nc\\\\x1b\\[31m\\|\\`x\\`&lt;script&gt;@channel\\\\u{202E}Z\\\\x85")
    assert markdown("# *a* _b_ [c](d) & e") == "\\# \\*a\\* \\_b\\_ \\[c\\](d) &amp; e"


def test_code_span_fence_is_longer_than_any_backtick_run():
    assert code_span("a``b") == "```a``b```"
    assert code_span("`edge`") == "`` `edge` ``"
    assert code_span("x|y", table=True) == "`x\\|y`"
    assert code_span("x|y") == "`x|y`"
    assert code_span("\x1b[0m") == "`\\x1b[0m`"


def test_message_keeps_text_but_shows_hidden_characters():
    assert message(HOSTILE) == "a\tb\nc\x1b[31m|`x`<script>@channel\\u{202E}Z\\u{0085}"


def test_codequality_is_the_terminal_rule():
    assert codequality(HOSTILE) == terminal(HOSTILE)


def test_log_lines_keeps_a_line_from_being_read_as_a_workflow_command():
    # Spec 6.13, D58: GitHub Actions runs a log line whose first non-blank characters are `::`; the runner trims
    # every kind of blank first, a no-break space included.
    assert log_lines("::error title=x::pwn\n") == "\\x3a:error title=x::pwn\n"
    assert log_lines("ok\n  ::add-mask::word\n\u00a0::stop-commands::t") == (
        "ok\n  \\x3a:add-mask::word\n\u00a0\\x3a:stop-commands::t")
    assert log_lines("a::b\n:one\n  low SW-SKL-031 ::x/SKILL.md:1\n") == "a::b\n:one\n  low SW-SKL-031 ::x/SKILL.md:1\n"
