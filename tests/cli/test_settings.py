"""Spec 6.3: `.spellwarden/config.yml`, unknown keys refused, `probe-private`
never a settings key, flag over environment over file over default."""
from __future__ import annotations

import fnmatch
import itertools
import time
import types

import pytest
from conftest import write_tree

from spellwarden_cli.settings import Flags, Settings, SettingsError, env_bool, glob_match, load_settings
from spellwarden_scan import glob as glob_module

CONFIG = ".spellwarden/config.yml"


def _load(tmp_path, text=None, *, flags=None, env=None, config=None):
    if text is not None:
        write_tree(tmp_path, {CONFIG: text})
    return load_settings(str(tmp_path), config=config, flags=flags or Flags(), env=env or {})


def test_defaults_without_a_file(tmp_path):
    assert _load(tmp_path) == Settings()


def test_the_file_is_read(tmp_path):
    settings = _load(tmp_path, "version: 1\ninclude: ['**/*.json']\nexclude: ['tests/fixtures/**']\n"
                               "fail-on: medium\nprobe: true\ntelemetry: false\n")
    assert settings == Settings(include=("**/*.json",), exclude=("tests/fixtures/**",), fail_on="medium", probe=True,
                                probe_private=False, telemetry=False)


@pytest.mark.parametrize("text, words", [
    ("version: 1\nfail_on: high\n", "unknown key 'fail_on'"),
    ("version: 1\nprobe-private: true\n", "probe-private"),
    ("version: 2\n", "`version` must be 1"),
    ("fail-on: high\n", "`version` must be 1"),
    ("version: 1\nfail-on: severe\n", "`fail-on`"),
    ("version: 1\nprobe: 'yes please'\n", "`probe`"),
    ("version: 1\ninclude: '*.md'\n", "`include`"),
    ("- version\n", "mapping"),
    ("version: 1\nx: &a 1\ny: *a\n", "anchor"),
])
def test_invalid_files_are_errors(tmp_path, text, words):
    with pytest.raises(SettingsError) as caught:
        _load(tmp_path, text)
    assert words in str(caught.value)
    assert CONFIG in str(caught.value)


def test_precedence_flag_then_environment_then_file_then_default(tmp_path):
    write_tree(tmp_path, {CONFIG: "version: 1\nfail-on: low\nprobe: true\n"})
    assert _load(tmp_path).fail_on == "low"
    assert _load(tmp_path, env={"SPELLWARDEN_FAIL_ON": "critical"}).fail_on == "critical"
    assert _load(tmp_path, flags=Flags(fail_on="medium"), env={"SPELLWARDEN_FAIL_ON": "critical"}).fail_on == "medium"
    assert _load(tmp_path).probe is True
    assert _load(tmp_path, env={"SPELLWARDEN_PROBE": "false"}).probe is False
    assert _load(tmp_path, flags=Flags(probe=False), env={"SPELLWARDEN_PROBE": "true"}).probe is False


def test_probe_private_comes_only_from_the_flag_or_the_environment(tmp_path):
    assert _load(tmp_path).probe_private is False
    assert _load(tmp_path, env={"SPELLWARDEN_PROBE_PRIVATE": "true"}).probe_private is True
    # The wrapper input false is passed as --no-probe-private and outranks the environment (C14).
    assert _load(tmp_path, flags=Flags(probe_private=False), env={"SPELLWARDEN_PROBE_PRIVATE": "true"}).probe_private is False


@pytest.mark.parametrize("env", [{"SPELLWARDEN_TELEMETRY": "off"}, {"SPELLWARDEN_TELEMETRY": "0"},
                                 {"SPELLWARDEN_TELEMETRY": "false"}, {"SPELLWARDEN_TELEMETRY": "no"}, {"DO_NOT_TRACK": "1"}])
def test_telemetry_is_off_with_any_opt_out(tmp_path, env):
    assert _load(tmp_path, env=env).telemetry is False


def test_telemetry_off_in_the_file_or_by_flag(tmp_path):
    assert _load(tmp_path, flags=Flags(telemetry=False)).telemetry is False
    assert _load(tmp_path, "version: 1\ntelemetry: false\n", env={"SPELLWARDEN_TELEMETRY": "on"}).telemetry is False


def test_bad_environment_values_are_errors(tmp_path):
    with pytest.raises(SettingsError, match="SPELLWARDEN_FAIL_ON"):
        _load(tmp_path, env={"SPELLWARDEN_FAIL_ON": "severe"})
    with pytest.raises(SettingsError, match="SPELLWARDEN_PROBE"):
        _load(tmp_path, env={"SPELLWARDEN_PROBE": "maybe"})


def test_config_flag_reads_another_file(tmp_path):
    other = tmp_path / "elsewhere.yml"
    other.write_text("version: 1\nfail-on: never\n")
    write_tree(tmp_path, {CONFIG: "version: 1\nfail-on: low\n"})
    assert _load(tmp_path, config=str(other)).fail_on == "never"
    with pytest.raises(SettingsError):
        _load(tmp_path, config=str(tmp_path / "missing.yml"))


def test_an_oversized_file_is_refused(tmp_path):
    with pytest.raises(SettingsError, match="too_large"):
        _load(tmp_path, "version: 1\n# " + "x" * (64 * 1024) + "\n")


def test_env_bool():
    assert [env_bool(v) for v in ("1", "TRUE", "yes", "On", "0", "false", "NO", "off", "", "maybe", None)] == [
        True, True, True, True, False, False, False, False, None, None, None]


@pytest.mark.parametrize("path, pattern, expected", [
    ("tests/fixtures/a/b.md", "tests/fixtures/**", True), ("a.md", "*.md", True), ("x/a.md", "*.md", False),
    ("x/a.md", "**/*.md", True), ("a.md", "**/*.md", True), ("x/y/z", "x/*/z", True), ("x/y/w/z", "x/*/z", False),
    ("x/y/w/z", "x/**/z", True), ("x", "x/**", True),
])
def test_glob_match(path, pattern, expected):
    assert glob_match(path, pattern) is expected


def _reference_glob_match(path, pattern):
    """The matcher of c709be0, kept as the oracle: exponential on runs of `**`, so only fed small cases."""
    def match(parts, segments):
        if not segments:
            return not parts
        head, rest = segments[0], segments[1:]
        if head == "**":
            return any(match(parts[index:], rest) for index in range(len(parts) + 1))
        return bool(parts) and fnmatch.fnmatchcase(parts[0], head) and match(parts[1:], rest)
    return match(path.split("/"), pattern.strip("/").split("/"))


def _joined(alphabet, longest):
    for size in range(1, longest + 1):
        yield from ("/".join(word) for word in itertools.product(alphabet, repeat=size))


def test_glob_match_agrees_with_the_previous_matcher():
    patterns = list(_joined(("a", "*", "?", "[!a]", "**"), 4))
    patterns += ["/" + p for p in patterns[:30]] + [p + "/" for p in patterns[:30]] + ["", "/", "a//b", "**//a"]
    paths = list(_joined(("a", "b", "ab", ""), 4))
    differences = [(path, pattern) for pattern in patterns for path in paths
                   if glob_match(path, pattern) is not _reference_glob_match(path, pattern)]
    assert differences == []


def _counting_fnmatch(monkeypatch, budget):
    calls = []

    def fnmatchcase(name, pattern):
        calls.append(1)
        if len(calls) > budget:
            raise AssertionError(f"more than {budget} segment comparisons")
        return fnmatch.fnmatchcase(name, pattern)
    monkeypatch.setattr(glob_module, "fnmatch", types.SimpleNamespace(fnmatchcase=fnmatchcase))
    return calls


@pytest.mark.parametrize("pattern", [
    "/".join(["**"] * 60 + ["nomatch"]), "/".join(["**", "a"] * 30 + ["nomatch"]), "/".join(["**", "*"] * 30 + ["b"]),
])
def test_glob_match_does_at_most_one_comparison_per_path_and_pattern_segment(monkeypatch, pattern):
    path = "/".join(["a"] * 200)
    calls = _counting_fnmatch(monkeypatch, budget=200 * len(pattern.split("/")))
    assert glob_match(path, pattern) is False
    assert calls


def test_glob_match_with_many_double_stars_is_fast():
    path = "/".join(["a"] * 200)
    started = time.perf_counter()
    assert glob_match(path, "/".join(["**"] * 60 + ["nomatch"])) is False
    assert glob_match(path, "/".join(["**", "a"] * 30 + ["nomatch"])) is False
    assert glob_match(path, "/".join(["**", "a"] * 30 + ["**"])) is True
    assert time.perf_counter() - started < 1.0


def test_glob_match_on_the_longest_pattern_a_config_scalar_allows():
    """A 4,096-character scalar (spec 6.3) holds about 2,000 segments; no recursion limit may be reached."""
    deep = "/".join(["a"] * 2048)
    assert glob_match(deep, "/".join(["**"] * 2048)) is True
    assert glob_match(deep, "/".join(["a"] * 2048)) is True
    assert glob_match(deep, "/".join(["**"] * 2047 + ["b"])) is False
