"""Engine 1.24.0 (speed and deadline spec 5.1, 5.2): the inputs of `benchmarks/speed_profile.py` are deterministic, exactly the size
asked for, built from the characters the spec names, and never written, printed or drawn from the `random` module. The reduced
sizes are the ones tests/golden/record_1_23_0_findings.py and the speed changes' tests use. `benchmarks/` is not in an sdist, so this
file skips there, as tests/test_disguise.py does."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "benchmarks" / "speed_profile.py"
if not SCRIPT.exists():
    pytest.skip("benchmarks/ is not in an sdist", allow_module_level=True)

_spec = importlib.util.spec_from_file_location("speed_profile_under_test", SCRIPT)
speed = importlib.util.module_from_spec(_spec)
sys.modules["speed_profile_under_test"] = speed
_spec.loader.exec_module(speed)

from spellwarden_scan import normalise  # noqa: E402

SIZE = 64 * 1024


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_the_constants_of_the_full_size_inputs():
    assert speed.FULL == 10_485_760 and len(speed.SKILL_MD) == 31
    assert len(speed.SKILL_MD) + 5 * speed.FULL == 52_428_831  # case (c)


def test_every_input_has_exactly_the_size_asked_for():
    for size in (1_000, SIZE, 100_003):
        generated = speed.generated_cases(size)
        assert list(generated) == list(speed.CASE_IDS)
        for case, files in generated.items():
            length = len(files["docs/guide.md"])
            assert (case, length) == (case, size) or (case == "nested-base64-line" and 0.99 * size <= length <= size)
            assert files["SKILL.md"] == speed.SKILL_MD
        for line in speed.normalise_lines(size).values():
            assert len(line) <= size
    assert len(speed.lookalike_line(SIZE)) == SIZE and len(speed.lookalike_line(SIZE).decode("utf-8")) < SIZE
    big = speed.big_skill(size=4_096)
    assert sorted(big) == ["SKILL.md"] + [f"docs/part-{part}.md" for part in range(1, 6)]
    assert sum(len(data) for data in big.values()) == 31 + 5 * 4_096


# These hashes are what makes "the same bytes on every Python version" a test: change the generator, and they change.
PINNED = {
    "ordinary": "cf2482a4707c8bf2b269edc0a7299e30642f558f562878c38f7a9138e0a38878",
    "worst": "a4fddc0d5fdd79e4453e38e689bba432ff198109f73caa17d6e3284248107a45",
    "base64-line": "68908b45563e18c02d94e2e5aa4a54c200331b3b94a1420d246f35dda2b825c1",
    "lookalike-line": "b1afa4bdb4976f275160512ddff5509fad429f89b329c37436c592cd992dc245",
    "nested-base64-line": "2ba40ece5e3164763ce7db51098c08638b6ad0571bb1fb416da13d242f8f9aed",
}


def test_the_bytes_are_the_pinned_bytes_on_every_run():
    for case, files in speed.generated_cases(SIZE).items():
        assert sha(files["docs/guide.md"]) == PINNED[case], case
    big = speed.big_skill(size=4_096)
    assert sha(b"".join(big[path] for path in sorted(big))) == "50718aa2a8075ce7c299e59035f6db281ebf4815b0b6b261d8d98a72ed39b147"
    lines = json.dumps(speed.normalise_lines(2_048), sort_keys=True).encode()
    assert sha(lines) == "730878a58c425ffe67d8cfe3dafc941e8107c6b73b610393f245dffcc7bd2b39"


def test_another_seed_gives_other_bytes():
    assert speed.ordinary_markdown(SIZE, "other") != speed.ordinary_markdown(SIZE)
    assert speed.worst_case(SIZE, "other") != speed.worst_case(SIZE)
    assert speed.number("a", 1) != speed.number("a", 2) != speed.number("b", 2)


def test_the_ordinary_markdown_is_ascii_with_short_lines_and_risky_commands_now_and_then():
    text = speed.ordinary_markdown(2**17)
    assert text.isascii()
    lines = text.decode("ascii").split("\n")
    assert max(len(line) for line in lines) <= 94
    for needle in ("```bash", "| name | value |", "- install", "](https://example.com/docs/", "| sh", "~/.ssh/id_rsa", "~/.aws/credentials",
                   "pip install requests", "## Step"):
        assert any(needle in line for line in lines), needle


def test_the_worst_case_is_built_for_the_normalised_pass():
    text = speed.worst_case(2**17).decode("utf-8")
    lines = text.split("\n")
    short = max(2**17 // 500, 64)
    assert max(len(line) for line in lines) >= 10 * short  # the long lines that mix everything
    changed = [line for line in lines if normalise.fold(line) != line]
    assert len(changed) >= 0.6 * len(lines)  # nearly every line changes under the fold steps
    assert sum(1 for line in lines if normalise.payloads(line)) >= len(lines) // 6  # a base64 payload in the lines of that kind
    for needle in ("\u0430", "&#105;", "\u200b", "  ", "\uff11", "\ufdfa"):
        assert needle in text, needle


def test_a_layered_payload_decodes_back_through_the_engines_own_decoder():
    for layers in (1, 2, 3):
        token = speed.layered("the quick brown fox jumps over the lazy dog 7", layers)
        assert normalise.payloads(f"x {token} y") == ("the quick brown fox jumps over the lazy dog 7",)


def test_the_lines_of_the_normalise_names_are_those_of_test_linear_time():
    lines = speed.normalise_lines(1_000)
    assert sorted(lines) == ["U+FDFA", "base64 alphabet", "character references", "look-alike letters", "nested base64",
                             "spaces and tabs", "zero-width runs"]
    assert lines["look-alike letters"].startswith("\u0430b \u0430b ") and lines["zero-width runs"].startswith("a\u200b\u200ca\u200b\u200c")
    assert normalise.payloads(lines["nested base64"])  # three layers of `a b ` text, the engine finds a payload


def test_the_script_uses_no_random_module_and_writes_nothing_and_prints_nothing_of_the_inputs():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert "random" not in imported and not imported & {"os", "pathlib", "tempfile", "shutil", "subprocess", "socket", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            assert name not in ("open", "write", "write_text", "write_bytes", "mkdir"), name
