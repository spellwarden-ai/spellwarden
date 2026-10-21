"""Phase C spec 5.2.2 and plan decision P-ORG-1: the pattern language of org rules (claim E2), its windows, its
`Then`-style evaluation and its bounded time (claim E4, the pattern half; the budget half is in test_orgrules.py)."""
from __future__ import annotations

import re
import time

import pytest

from spellwarden_scan.orgrules import PATTERN_LIMITS, OrgRuleError, compile_pattern, pattern_search, unit_windows


def code_of(pattern: str) -> str:
    with pytest.raises(OrgRuleError) as caught:
        compile_pattern(pattern)
    assert caught.value.message.endswith(".") and caught.value.message == str(caught.value)
    return caught.value.code


def test_the_limits_are_the_numbers_of_spec_5_2_2():
    assert dict(PATTERN_LIMITS) == {"max_length": 300, "max_parts": 4, "max_groups": 4, "max_alternatives": 16,
                                    "max_class_members": 64, "max_repeat": 100, "max_repeat_range": 400,
                                    "window": 4096, "overlap": 512}
    with pytest.raises(TypeError):
        PATTERN_LIMITS["window"] = 1  # type: ignore[index]


@pytest.mark.parametrize("pattern", [
    "curl", r"a\.b", r"a\/b", r"a\-b", r"\\x", r"a\(b\)", r"\[x\]", r"a\{1\}", r"\^a\$", r"a\|b", r"a\*", r"a\+b\?",
    "a.c", r"x\s\S\d\D\w\W", "[a-z]", "[^0-9]", r"[a-z0-9_\-]", "[-a]", "[a-]", r"[\s\d]", r"\bword\b", "^start",
    "end$", "^only$", "colou?r", "xa*b", "xa+b", "x[0-9]{3}y", "x[0-9]{1,3}y", "(curl|wget) ", "x(ab|cd)?y",
    r"(curl|wget)\s.*https?://[0-9]{1,3}\.[0-9]{1,3}\.", "a.*b.*c.*d", "(a|b)(c|d)(e|f)(g|h)",
    "(" + "|".join("abcdefghijklmnop") + ")", "[" + "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!#" + "]",
    "x{100}", "x" * 300, "naïve 运维",
])
def test_each_allowed_construct_compiles(pattern):
    compiled = compile_pattern(pattern)
    assert compiled.source == pattern and compiled.parts


@pytest.mark.parametrize("pattern", [
    r"(a)\1", r"x\1", "a(?=b)", "a(?!b)", "(?<=a)b", "(?<!a)b", "(?i)abc", "(?P<n>a)", "(?:a)", "xa*?b", "xa+?b", "xa??b",
    "xa{1,2}?b", "xa*+b", "a{2,}", "a{,2}", "a{x}", "a|b", "(a(b))", "(ab)+", "(ab)*", "(ab){2}", r"\Aabc", r"abc\Z",
    r"\Gabc", r"\x41", "\\" + "u0041", r"\N{DASH}", r"\0", r"\t", "a^b", "a$b", "*a", "a**", "(a|)", "(|a)", "()", "(ab",
    "ab)", "[]", "[abc", "[a[b]]", "[[:alpha:]]", "[z-a]", r"[\d-z]", "[a-c-e]", "]", "a}", "x\\", "", ".*abc", "abc.*",
    "a.*.*b", "^.*b", r"\b.*x", "a{3,1}", "a{0}", "x.*?y", "x.*+y",
])
def test_constructs_outside_the_language_are_pattern_syntax(pattern):
    assert code_of(pattern) == "pattern_syntax"


@pytest.mark.parametrize("pattern", [
    "xa+b+", "x.+y+z", "a.*b.*c.*d.*e", "(a|b)(c|d)(e|f)(g|h)(i|j)", "(" + "|".join("abcdefghijklmnopq") + ")",
    "[" + "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!#$" + "]", "xa{1,101}", "(a+|b)", "(a*)",
    "(a.*b)",
    # plan decision P-ORG-1: a part may not start with an unbounded repeat, and a repeat may not sit next to an item
    # that matches the same characters
    "a*b", r"\s+x", "x?a+b", r"x\s*\s", "xa+a", "xa{1,5}a", "x.{0,100}y", "x[a-z]+[a-c]", "(ab|xa)a+b", "x(b|c){0,1}",
    "q[a-z]+0", "xa?A", "xk+\U0000212a",
])
def test_valid_constructs_beyond_the_counts_or_the_cost_rules_are_pattern_too_complex(pattern):
    if pattern == "x(b|c){0,1}":  # a quantified group is a syntax error, whatever the count
        assert code_of(pattern) == "pattern_syntax"
        return
    assert code_of(pattern) == "pattern_too_complex"


def test_length_301_is_pattern_too_long_and_300_compiles():
    assert code_of("x" * 301) == "pattern_too_long"
    compile_pattern("x" * 300)
    assert code_of(5) == "pattern_syntax"  # type: ignore[arg-type]


def test_the_message_names_the_position():
    with pytest.raises(OrgRuleError) as caught:
        compile_pattern("curl(ab)+cd")
    assert caught.value.message == ("The pattern has a quantifier on a group at character 9. "
                                    "Quantify one character or class instead.")
    with pytest.raises(OrgRuleError) as caught:
        compile_pattern(r"x\s*\s")
    assert "character 2" in caught.value.message and "character 5" in caught.value.message


def test_compilation_gives_one_python_pattern_per_part_and_one_pcre_string():
    compiled = compile_pattern(r"(curl|wget)\s.*https?://[0-9]{1,3}\.[0-9]{1,3}\.")
    assert [p.pattern for p in compiled.parts] == [r"(?:curl|wget)\s", r"https?://[0-9]{1,3}\.[0-9]{1,3}\."]
    assert all(p.flags & re.IGNORECASE for p in compiled.parts)
    assert compiled.pcre == r"(?i)(?:curl|wget)\s.*https?://[0-9]{1,3}\.[0-9]{1,3}\."
    exact = compile_pattern("^Sudo su$", case_sensitive=True)
    assert exact.pcre == r"^Sudo\ su$" and not exact.parts[0].flags & re.IGNORECASE and exact.anchored_end


@pytest.mark.parametrize("pattern", [
    r"(curl|wget)\s.*https?://", r"[^a-z\-]{2,5}x", r"a\.b\/c\-d\(e\)", "naïve 运维", r"\bx\b", "^a.*b$", "x(ab|c)?y",
])
def test_every_pcre_form_compiles_in_python_and_uses_no_python_only_syntax(pattern):
    pcre = compile_pattern(pattern).pcre
    re.compile(pcre)
    assert not any(token in pcre for token in ("(?P", "(?#", "(?<", "\\A", "\\Z"))


def test_windows_of_spec_5_2_2():
    assert list(unit_windows("")) == [(0, 0)]
    assert list(unit_windows("x" * 4096)) == [(0, 4096)]
    assert list(unit_windows("x" * 4097)) == [(0, 4096), (3584, 4097)]
    assert list(unit_windows("x" * 10_000)) == [(0, 4096), (3584, 7680), (7168, 10_000)]


def test_then_evaluation_reads_the_parts_in_order():
    compiled = compile_pattern(r"curl .*\-d\b")
    assert pattern_search(compiled, "curl https://x -d @f")
    assert not pattern_search(compiled, "-d then curl x")
    assert pattern_search(compile_pattern("CURL"), "curl x")
    assert not pattern_search(compile_pattern("CURL", case_sensitive=True), "curl x")


def test_a_match_far_into_a_long_line_is_found_through_the_windows():
    line = "a" * 10_000 + "needle" + "b" * 9_994
    assert len(line) == 20_000 and pattern_search(compile_pattern("needle"), line)
    crossing = "x" * 4090 + "needle" + "y" * 5000  # crosses the first window's end, inside the overlap
    assert pattern_search(compile_pattern("needle"), crossing)


def test_a_match_longer_than_the_overlap_across_a_window_boundary_is_missed_as_documented():
    line = "x" * 3500 + "start" + "y" * 700 + "stop" + "z" * 10_000
    assert not pattern_search(compile_pattern("start.*stop"), line)
    assert pattern_search(compile_pattern("start.*stop"), "start" + "y" * 700 + "stop")


def test_anchors_hold_at_the_ends_of_the_unit_not_of_a_window():
    long = "q" * 9_000 + "abc"
    assert pattern_search(compile_pattern("abc$"), long)
    assert not pattern_search(compile_pattern("abc$"), "q" * 4093 + "abc" + "q" * 5000)
    assert not pattern_search(compile_pattern("^q{3}x"), "z" * 3584 + "qqqx")
    assert pattern_search(compile_pattern("^q{3}x"), "qqqx" + "z" * 9000)
    assert pattern_search(compile_pattern(r"\bword"), "a" * 3583 + " word" + "b" * 5000)


N = 100_000
_G16 = "(" + "|".join("abcdefghijklmnop") + ")"
_GB = "(" + "|".join(f"{c}{{1,34}}" for c in "abcd") + ")"
_GA = "(" + "|".join("a{0,100}" + c for c in "bcde") + ")?"
WORST = [
    (r"x\s+y", ["x" + " " * N, "x " * (N // 2), " " * N]),
    (r"a\s+b.*c\s+d.*e\s+f.*g\s+h", ["a" + " " * N, "a b c d e f g " * (N // 14)]),
    (r"\s".join([_G16] * 4) + r"\d", ["a" * N, "a " * (N // 2), "a b c d " * (N // 8)]),
    (_GB + r"\s" + _GB + r"\s" + _GB + r"[0-9]", ["a" * N, ("a" * 100 + " ") * (N // 101), "a b " * (N // 4)]),
    (r"[0-9]{1,100}\s[0-9]{1,100}\s[0-9]{1,100}\s[0-9]{1,100}[a-f]", ["1" * N, ("1" * 100 + " ") * (N // 101)]),
    (r"\w{1,100}\s{1,100}\d{1,100}\W", ["a" * N, ("a" * 100 + " " * 100) * (N // 200)]),
    (".*".join([r"[0-9]{1,100}\s[a-f]"] * 4), ["1" * N, ("1" * 100 + " ") * (N // 101)]),
    (r"z[0-9]{1,100}\s[a-f]+[0-9]{1,100}\s[g-k]", ["z1 a1 g" * (N // 7), "z" + "1" * 100 + " " + "a" * N]),
    (_GA + "z", ["a" * N]),
    ("(" + "|".join("a{0,25}" + c for c in "bcdefghijklmnopq") + ")?z", ["a" * N]),
    (".*".join(["(" + "|".join("a{0,50}" + c for c in "bcdefghi") + ")?z"] * 2), ["a" * N, ("a" * 60 + "z") * (N // 61)]),
]


def test_repeats_may_vary_by_at_most_400_characters_in_one_part():
    # review of 2026-10-21: sixteen alternatives `a{0,99}b` read 0.8 s per 100 000 characters and two such groups 1.7 s
    group = "(" + "|".join("a{0,99}" + c for c in "bcdefghijklmnopq") + ")?"
    for pattern in (group + "z", group + group + "z", "a{0,100}b{0,100}c{0,100}d{0,100}e?f"):
        with pytest.raises(OrgRuleError) as caught:
            compile_pattern(pattern)
        assert caught.value.code == "pattern_too_complex"
        assert "at most 400" in caught.value.message
    compile_pattern("a{0,100}b{0,100}c{0,100}d{0,100}e")
    compile_pattern(".*".join(["a{0,100}b{0,100}c{0,100}d{0,100}e"] * 4))


def test_overlap_is_decided_on_every_character_not_on_a_sample():
    # security review of 2026-10-21: a negated class that leaves out only the sampled digits passed next to `\d`
    for pattern in ("\\d{0,99}[^0-9\u0660-\u0669\u06f0-\u06f9\u0966-\u096f\uff10-\uff19\U0001d7ce-\U0001d7ff]",
                    "\\w{1,99}[\u4e01-\u4e02]", "k{0,9}\u212a"):
        with pytest.raises(OrgRuleError) as caught:
            compile_pattern(pattern)
        assert caught.value.code == "pattern_too_complex"
    compile_pattern(r"\w{0,9}\s")
    compile_pattern("[^a]{0,9}a")
    compile_pattern("a{0,99}[\u0100-\u2000]")


@pytest.mark.parametrize("pattern, lines", WORST, ids=[p[:24] for p, _ in WORST])
def test_the_worst_allowed_shapes_read_a_100_000_character_adversarial_line_in_under_one_second(pattern, lines):
    compiled = compile_pattern(pattern)
    for line in lines:
        started = time.perf_counter()
        pattern_search(compiled, line)
        assert time.perf_counter() - started < 1.0
