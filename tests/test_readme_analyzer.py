"""Phase 4 batch B spec 11.3, 4.8, 4.10 and spec:Q4: the README's "Model-assisted analyzer" section states the flags, the key's
one source, the address rules and bounds of `model_client`, what is sent and what comes back as `spellwarden_scan.analyzer`
defines them, the guide link with its campaign tags and the one line the release fills with the measured rates; "Limits" records
the analyzer's bound, the file that is not text and the answer bound, with the scan's exit code unchanged; "Exit codes" says
neither the lint nor the analyzer changes it."""
from __future__ import annotations

import re
from pathlib import Path

from spellwarden_scan import analyzer
from spellwarden_cli import model_client

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
GUIDE = "https://spellwarden.ai/docs/model-assisted-analyzer?utm_source=scanner&utm_medium=cli&utm_campaign=analyzer"


def section(heading: str) -> str:
    start = README.index(heading)
    return README[start:README.index("\n### ", start + len(heading))]


def test_the_section_states_the_flags_the_key_and_the_rules():
    text = section("### Model-assisted analyzer: `--analyze`")
    for needle in ("Off by default", "--model-endpoint", "--model NAME", "--analyze-max-bytes N", "--analyze-cache DIR",
                   "`SPELLWARDEN_MODEL_KEY` only, never a flag", "`Authorization: Bearer`", "Nothing goes to Spellwarden",
                   "`http` only for a loopback address", "No redirect is followed", "10 s to connect and 120 s",
                   "over 1 MiB", "`mask_credentials`", "random boundary", "nonce", "never clean", "`model_assisted`",
                   "level `note` with `properties.model_assisted: true`", "never changes the exit code", "Unmeasured model",
                   "On Windows a file git does not track has no executable mode", "`exec_bits_unknown`"):
        assert needle in text, needle
    assert all(f"`{category}`" in text for category in analyzer.CATEGORIES)
    assert all(f"`{extension}`" in text for extension in analyzer.SCRIPT_EXTENSIONS)
    assert (model_client.CONNECT_TIMEOUT_SECONDS, model_client.READ_TIMEOUT_SECONDS, model_client.ANSWER_MAX) == (10.0, 120.0, 2**20)
    assert (analyzer.MAX_SPANS, analyzer.SUMMARY_MAX, analyzer.SPAN_MAX) == (5, 300, 200)
    assert f"]({GUIDE})" in text
    assert not re.search("[\u2013\u2014!]", text)


def test_the_measured_rates_line_is_there_once_for_the_release_to_fill():
    assert README.count("Measured rates: filled before the release") == 1
    assert "\nMeasured rates: filled before the release\n" in section("### Model-assisted analyzer: `--analyze`")


def test_limits_records_the_analyzer_s_bounds_and_spec_q4():
    text = section("### Limits")
    assert analyzer.ANALYZER_MAX_BYTES == 120_000
    for needle in ("at most 120,000 bytes", "`too_large`", "`not_text`", "`analysis_incomplete`", "--analyze-max-bytes",
                   "never shown as analysed or clean", "the scan's errors and its exit code stay as the rules left them",
                   "over 1 MiB", "`spans_left_out`"):
        assert needle in text, needle


def test_exit_codes_say_neither_the_lint_nor_the_analyzer_changes_them():
    assert "Neither the description lint nor the model-assisted analyzer (`--analyze`) ever changes the exit code" in section(
        "### Exit codes")
