"""Security review: no detector backtracks quadratically. A crafted skill line that repeats the first half of a
pattern (`curl `, `iex(`, `eyJ`, `open(`) without the second half once took hours at the 1 MB text limit. Every
matcher here must read a 100 000-character line in well under a second; the quadratic forms took tens of seconds."""
from __future__ import annotations

import time

import pytest

from spellwarden_scan import RuleSet, scan_skill_package
from spellwarden_scan.evidence import mask_credentials
from spellwarden_scan.rules import mcp, skill
from spellwarden_scan.rules import patterns as P

N = 100_000
BUDGET_SECONDS = 1.0

CASES = [
    (skill._PIPED, "iex("), (skill._PIPED, "curl "), (skill._PIPED, "iwr "), (skill._SEND, "curl "), (skill._SEND, "scp "),
    (skill._SEND, "fetch("), (skill._SEND, "rsync "), (skill._DESTRUCTIVE, "az "), (skill._DESTRUCTIVE, "git push "),
    (skill._WRITE_VERB, "open("), (skill._WRITE_VERB, "jq "), (skill._SKIP, '"permissions":{'), (skill._COMPILE_EXEC, "compile("),
    (skill._CHR_JOIN, "chr(1)" + " " * 40), (mcp._TOOL_INJECTION[4], "IMPORTANT:"),
    (P.CREDENTIAL_PATTERNS[10], "eyJ"), (P.CREDENTIAL_PATTERNS[4], "glpat-"),
]


def _line(token: str) -> str:
    return (token * (N // len(token) + 1))[:N]


@pytest.mark.parametrize("matcher, token", CASES, ids=[repr(token)[:20] for _, token in CASES])
def test_each_gap_pattern_reads_a_repeated_prefix_line_in_linear_time(matcher, token):
    line = _line(token)
    started = time.perf_counter()
    matcher.search(line)
    assert time.perf_counter() - started < BUDGET_SECONDS


def test_from_char_code_and_masking_are_linear():
    started = time.perf_counter()
    skill._char_codes(_line("String.fromCharCode("))
    mask_credentials(_line("token=a1"))
    mask_credentials(_line("eyJ"))
    assert time.perf_counter() - started < BUDGET_SECONDS


def test_a_whole_scan_of_adversarial_lines_stays_fast():
    body = "\n".join(_line(token)[: N // 10] for _, token in CASES)
    files = {"SKILL.md": f"---\nname: x\ndescription: y\n---\n{body}\n```bash\n{body}\n```\n".encode(), "scripts/a.sh": body.encode()}
    started = time.perf_counter()
    scan_skill_package(files, RuleSet.baseline())
    assert time.perf_counter() - started < 5 * BUDGET_SECONDS


def test_the_linear_matchers_keep_the_regex_meaning():
    assert P.Then("curl ", "-d\\b").search("curl https://x -d @f") and not P.Then("curl ", "-d\\b").search("-d then curl x")
    within = P.Within("open\\(", "[\"'][wa][\"']", ")")
    assert within.search("open(path, 'w')") and not within.search("open(path) 'w'")
    piped = P.Piped("curl\\b", "\\s*(sh|bash)\\b")
    assert piped.search("curl -s x | bash") and not piped.search("curl x | tee y | grep bash") and not piped.search("curl x || sh")
    assert P.AnyOf(P.Then("a", "b"), P.Then("c", "d")).search("c then d")
