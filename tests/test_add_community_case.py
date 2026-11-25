"""Community reports spec 11, claims A-1 to A-5: `scripts/add_community_case.py` turns the text of an issue form into a case of
`fixtures/community/`. Every body here is written in the shape GitHub renders a form, every run passes its own `--root` and
`--manifest` (so a test can never write into the real corpus), and nothing opens a network connection. The script is not in an
sdist, so this file skips when `scripts/` is absent."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from community_cases import CLEAN_SKILL, PIP_SKILL, SCRIPTS, load_script, write_manifest
from conftest import credential

if not SCRIPTS.is_dir():
    pytest.skip("scripts/ is not in an sdist", allow_module_level=True)

add = load_script("add_community_case.py", "spellwarden_add_community_case_test")
MARKER = "UNIQUE-SAMPLE-MARKER"
WINDOWS = os.name == "nt"


def issue_body(form: str = "missed-detection", *, sample: str = PIP_SKILL, file: str = "SKILL.md",
               versions: str = "spellwarden 1.23.0 (rules 2026.11.9)", more: str = "", origin: str = "I wrote it",
               credit: str = "", consent: str | None = None, fence: str | None = None, newline: str = "\n",
               tick: str = "x") -> str:
    """The body GitHub gives an issue made from a form: `### <label>`, a blank line, the answer; a `render: text` answer inside a
    fenced block whose fence is one backtick longer than the longest run in the text (at least three; `fence` forces one);
    `_No response_` for an empty optional field; a checkbox as `- [x] <option>`. Every field of the form is rendered, in the
    form's order, the fields the record does not keep included (r1:F1), as GitHub renders them."""
    labels = add.ALL_LABELS[form]

    def block(label: str, text: str) -> str:
        return f"### {label}\n\n{text}\n"

    def fenced(label: str, text: str) -> str:
        longest = max((len(run) for run in re.findall("`+", text)), default=0)
        ticks = fence or "`" * max(3, longest + 1)
        return block(label, f"{ticks}text\n{text.rstrip(chr(10))}\n{ticks}") if text else block(label, "_No response_")

    answers = {"versions": versions, "command": "spellwarden scan .", "file": file, "origin": origin, "source": "_No response_",
               "credit": credit or "_No response_",
               "consent": consent if consent is not None else f"- [{tick}] {add.CONSENT_TEXT}",
               # the fields of one form only: answered as a reporter would, a multi-line answer included
               "rule": "SW-SKL-009", "why": "It only greets the user.\n\nNothing runs.", "expected": "SW-SKL-009 at high",
               "detects": "A download piped into a shell.", "content": "A skill (SKILL.md and its files)",
               "gap": "SW-SKL-009 reads only one form of it.", "harmless": "A README that quotes the command."}
    parts = [fenced(labels[field], sample if field == "sample" else more) if field in ("sample", "more")
             else block(labels[field], answers[field]) for field in add.FIELD_ORDER[form]]
    return "\n".join(parts).replace("\n", newline)


@pytest.fixture
def run(tmp_path, capsys):
    """`run(body, *options, manifest=None) -> (exit code, stdout, stderr)`: writes the body to a file and runs the script with the
    corpus root `tmp_path/community` and a manifest of `tmp_path` (empty unless `manifest` gives the test-set files)."""
    root = tmp_path / "community"

    def go(body: str, *options: str, manifest: list[bytes] = (), kind: str = "miss", rule: str = "SW-SKL-009"):
        body_path = tmp_path / "body.md"
        body_path.write_bytes(body.encode("utf-8"))
        manifest_path = write_manifest(tmp_path / "manifest.json", test=list(manifest))
        code = add.main([str(body_path), "--kind", kind, "--rule", rule, "--issue", "68", "--date", "2026-11-26",
                         "--root", str(root), "--manifest", str(manifest_path), *options])
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    go.root = root
    return go


def _tree(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()} \
        if root.exists() else {}


# --- A-1: a body of each form gives the tree ---------------------------------------------------------------------------------

@pytest.mark.parametrize("form, kind, recorded", [("missed-detection", "miss", "miss"), ("new-rule", "miss", "miss"),
                                                    ("false-positive", "false-positive", "false_positive")])
def test_a_body_of_each_form_gives_the_expected_tree(run, form, kind, recorded):
    code, out, err = run(issue_body(form, credit="Ada Example", more="=== scripts/run.sh ===\necho hello\n"), kind=kind)
    assert (code, err) == (0, "")
    assert out.splitlines() == ["added COM-0001", f"{run.root.as_posix()}/COM-0001/record.json",
                                f"{run.root.as_posix()}/COM-0001/files/SKILL.md", f"{run.root.as_posix()}/COM-0001/files/scripts/run.sh"]
    tree = _tree(run.root)
    assert sorted(tree) == ["COM-0001/files/SKILL.md", "COM-0001/files/scripts/run.sh", "COM-0001/record.json"]
    assert tree["COM-0001/files/SKILL.md"] == PIP_SKILL.encode() and tree["COM-0001/files/scripts/run.sh"] == b"echo hello\n"
    assert b"\r" not in b"".join(tree.values())
    record = json.loads(tree["COM-0001/record.json"])
    assert record == {"id": "COM-0001", "kind": recorded, "rule": "SW-SKL-009", "kept_hosts": [],
                      "reported_against": {"scanner": "1.23.0", "rules": "2026.11.9"}, "outcome": "open", "fixed_in": None,
                      "credit": "Ada Example", "date": "2026-11-26", "issue": 68}
    corpus = add.corpus
    assert tree["COM-0001/record.json"].decode() == corpus.dump_record(record)
    assert [case.id for case in corpus.load_cases(run.root)] == ["COM-0001"]
    if not WINDOWS:
        assert all(not (path.stat().st_mode & 0o111) for path in run.root.rglob("*") if path.is_file())


def test_a_second_run_gives_the_next_id_and_a_ticked_box_is_read_in_both_cases(run):
    assert run(issue_body(tick="x"))[0] == 0
    code, out, _err = run(issue_body(sample=CLEAN_SKILL, tick="X"), kind="false-positive")
    assert code == 0 and out.splitlines()[0] == "added COM-0002"


def test_a_fixed_case_takes_the_release_and_the_versions_may_be_two_bare_numbers(run):
    code, _out, err = run(issue_body(versions="1.23.0, 2026.11.9"), "--outcome", "fixed", "--fixed-in", "1.24.0")
    assert (code, err) == (0, "")
    record = json.loads((run.root / "COM-0001" / "record.json").read_text(encoding="utf-8"))
    assert record["outcome"] == "fixed" and record["fixed_in"] == "1.24.0" and record["reported_against"]["rules"] == "2026.11.9"


def test_a_case_from_private_reporting_has_no_issue_number(tmp_path, capsys):
    body = tmp_path / "body.md"
    body.write_text(issue_body(), encoding="utf-8")
    manifest = write_manifest(tmp_path / "manifest.json")
    assert add.main([str(body), "--kind", "miss", "--rule", "SW-SKL-009", "--outcome", "fixed", "--fixed-in", "1.24.0",
                     "--date", "2026-11-26", "--root", str(tmp_path / "c"), "--manifest", str(manifest)]) == 0
    assert json.loads((tmp_path / "c" / "COM-0001" / "record.json").read_text(encoding="utf-8"))["issue"] is None
    capsys.readouterr()


def test_a_host_kept_with_keep_host_is_accepted_and_recorded_sorted(run):
    sample = PIP_SKILL + "\nSee https://paste.example.io/raw/1 for the text.\n"
    refused = run(issue_body(sample=sample))
    assert refused[0] == 2 and "names the host 'paste.example.io'" in refused[2]
    code, _out, err = run(issue_body(sample=sample), "--keep-host", "Zeta.Example.io", "--keep-host", "paste.example.io")
    assert (code, err) == (0, "")
    assert json.loads((run.root / "COM-0001" / "record.json").read_text(encoding="utf-8"))["kept_hosts"] == \
        ["paste.example.io", "zeta.example.io"]


# --- A-2: each refusal exits 2, writes nothing and prints no sample text ------------------------------------------------------

BIG = "# " + MARKER + "\n" + "a" * (64 * 1024 + 1) + "\n"
REFUSALS = [
    ("consent not ticked", dict(consent=f"- [ ] {add.CONSENT_TEXT}"), {}, "consent box is not ticked"),
    ("consent text changed", dict(consent="- [x] I agree to anything."), {}, "consent box is not ticked"),
    ("origin from a test set", dict(origin=add.ORIGIN_TEST_SET), {}, add.TEST_SET_REASON),
    ("origin not an option", dict(origin="somewhere"), {}, "origin is not one of the three options"),
    ("bad versions", dict(versions="version 1.23"), {}, "versions are not"),
    ("unknown rule", {}, dict(rule="SW-SKL-999"), "not a rule of the baseline"),
    ("an SW-MCP rule", {}, dict(rule="SW-MCP-001"), "area mcp"),
    ("an SW-REG rule", {}, dict(rule="SW-REG-001"), "area registry"),
    ("unsafe path", dict(file="../SKILL.md"), {}, "a segment .."),
    ("oversized sample", dict(sample=BIG), {}, "at most 65536"),
    ("binary text", dict(sample="# " + MARKER + "\nab\x00cd\n"), {}, "NUL byte"),
    ("live host", dict(sample=PIP_SKILL + MARKER + " https://evil.com/install.sh\n"), {}, "names the host 'evil.com'"),
    ("credential shape", dict(sample=PIP_SKILL + MARKER + " " + credential("github") + "\n"), {}, "shape of a GitHub token"),
    ("empty required field", dict(versions=""), {}, "the field 'Scanner version and rules version' is empty or missing"),
    ("not a form", None, {}, "not the answer of one of the three issue forms"),
]


@pytest.mark.parametrize("fields, options, expected", [row[1:] for row in REFUSALS], ids=[row[0] for row in REFUSALS])
def test_each_refusal_exits_2_writes_nothing_and_prints_no_sample_text(run, fields, options, expected):
    body = f"just a paragraph that says {MARKER}\n" if fields is None else issue_body(**{"sample": PIP_SKILL + MARKER + "\n", **fields})
    code, out, err = run(body, **options)
    assert code == 2 and out == ""
    assert expected in err
    assert not run.root.exists()
    assert MARKER not in out + err and "pip install" not in out + err
    assert all(line.startswith("refused: ") for line in err.splitlines())


def test_a_file_equal_to_a_test_set_file_is_refused_with_the_written_reason(run):
    sample = PIP_SKILL + "# a sample of more than two hundred bytes " + MARKER + "x" * 200 + "\n"
    code, out, err = run(issue_body(sample=sample), manifest=[sample.encode()])
    assert code == 2 and not run.root.exists() and MARKER not in out + err
    assert "'SKILL.md': the file equals a file of a set that the benchmark keeps as a test set" in err and add.TEST_SET_REASON in err
    code, _out, _err = run(issue_body(sample=sample + "changed\n"), manifest=[sample.encode()])
    assert code == 0


def test_a_duplicate_of_an_existing_case_is_refused(run):
    assert run(issue_body())[0] == 0
    before = _tree(run.root)
    code, out, err = run(issue_body(credit="Someone Else"))
    assert code == 2 and "the sample equals the sample of COM-0001" in err and out == "" and _tree(run.root) == before


def test_the_script_stops_at_the_first_group_that_fails_and_prints_all_of_that_group(run):
    code, _out, err = run(issue_body(consent=f"- [ ] {add.CONSENT_TEXT}", versions="x", origin=add.ORIGIN_TEST_SET),
                          rule="SW-SKL-999")
    assert code == 2 and err.splitlines() == ["refused: the consent box is not ticked, so the sample cannot be published under "
                                              "the repository's licence"]
    code, _out, err = run(issue_body(sample=PIP_SKILL + "https://evil.com/a https://bad.org/b\n" + credential("aws") + "\n"))
    lines = err.splitlines()
    assert code == 2 and len(lines) == 3 and sum("names the host" in line for line in lines) == 2


def test_the_options_that_do_not_fit_together_are_refused(run):
    assert "--outcome fixed needs --fixed-in" in run(issue_body(), "--outcome", "fixed")[2]
    assert "--fixed-in goes with --outcome fixed" in run(issue_body(), "--fixed-in", "1.24.0")[2]
    assert "--keep-host 'https://x.example' is not a bare lower-case host name" in run(issue_body(), "--keep-host", "https://x.example")[2]
    assert "before the version reported against" in run(issue_body(), "--outcome", "fixed", "--fixed-in", "1.22.0")[2]
    assert not run.root.exists()


# --- A-3: --dry-run ----------------------------------------------------------------------------------------------------------

def test_dry_run_writes_nothing_and_prints_the_same_every_time(run):
    first = run(issue_body(), "--dry-run")
    second = run(issue_body(), "--dry-run")
    assert first == second and first[0] == 0 and first[1].splitlines()[0] == "would add COM-0001"
    assert not run.root.exists()
    assert run(issue_body(consent=f"- [ ] {add.CONSENT_TEXT}"), "--dry-run")[0] == 2


# --- A-4: the other files, line endings, fences ---------------------------------------------------------------------------------

def test_the_other_files_are_split_with_crlf_bodies_and_a_longer_fence_is_read_whole(run):
    sample = PIP_SKILL + "\nA fence inside the sample:\n\n```\nnested\n```\n"
    more = "=== docs/a.md ===\none\ntwo\n=== b.md ===\nthree\n"
    code, _out, err = run(issue_body(sample=sample, more=more, fence="````", newline="\r\n"))
    assert (code, err) == (0, "")
    tree = _tree(run.root)
    assert tree["COM-0001/files/SKILL.md"] == sample.encode()
    assert tree["COM-0001/files/docs/a.md"] == b"one\ntwo\n" and tree["COM-0001/files/b.md"] == b"three\n"
    assert b"\r" not in b"".join(tree.values())


def test_a_three_backtick_outer_fence_around_a_sample_with_its_own_block_and_heading_is_read_whole(run):
    """GitHub fences a `render: text` answer with exactly three backticks, so a sample's own block and `### ` heading must not
    cut the answer short or hide the `more` field."""
    sample = PIP_SKILL + "\n### Notes\n\nKeep it short.\n"
    more = "=== scripts/run.sh ===\necho hello\n"
    code, _out, err = run(issue_body(sample=sample, more=more, fence="```"))
    assert (code, err) == (0, "")
    tree = _tree(run.root)
    assert tree["COM-0001/files/SKILL.md"] == sample.encode()
    assert tree["COM-0001/files/scripts/run.sh"] == b"echo hello\n"


def test_a_path_given_twice_or_text_before_the_first_marker_is_refused(run):
    assert "the path is also the file of the sample" in run(issue_body(more="=== SKILL.md ===\nx\n"))[2]
    assert "start with text before the first line" in run(issue_body(more="stray\n=== a.md ===\nx\n"))[2]
    assert "the path is given twice" in run(issue_body(more="=== a.md ===\nx\n=== a.md ===\ny\n"))[2]


@pytest.mark.parametrize("form", ["false-positive", "missed-detection", "new-rule"])
def test_a_sample_that_repeats_a_heading_of_the_form_is_refused_by_name_never_cut_short(run, form):
    """r1:F2: a sample line `### Publishing` (a skill about publishing a package) is a heading GitHub's body cannot tell apart
    from the form's own field; the case was committed cut short. It is refused, naming the heading."""
    sample = PIP_SKILL + "\n### Publishing\n\nRun twine upload when the tests pass.\n"
    code, _out, err = run(issue_body(form, sample=sample))
    assert code == 2 and "the body holds the heading ### Publishing more than once" in err
    assert not (run.root / "COM-0001").exists()
    sample = PIP_SKILL + "\n### Usage\n\nRun it.\n"   # a heading that is no label of the form is the sample's own text
    assert run(issue_body(form, sample=sample))[0] == 0


# --- A-5: the credit ---------------------------------------------------------------------------------------------------------

def test_an_empty_credit_is_null_and_a_name_is_trimmed(run):
    assert run(issue_body(credit=""))[0] == 0
    assert json.loads((run.root / "COM-0001" / "record.json").read_text(encoding="utf-8"))["credit"] is None
    assert run(issue_body(sample=CLEAN_SKILL, credit="  Ada Example  "))[0] == 0
    assert json.loads((run.root / "COM-0002" / "record.json").read_text(encoding="utf-8"))["credit"] == "Ada Example"


def test_a_credit_with_a_line_break_or_over_80_characters_is_refused(run):
    assert "the credit holds a line break" in run(issue_body(credit="Ada\nExample"))[2]
    assert "longer than 80 characters" in run(issue_body(credit="A" * 81))[2]
    assert run(issue_body(credit="A" * 80))[0] == 0


def test_a_credit_with_a_mention_a_link_or_markup_is_refused_and_a_plain_name_in_any_script_is_kept(run):
    """r0:F4: the credit is printed in the CHANGELOG and the release thread, so a mention, a link, a URL or markup is refused."""
    for credit in ("[Ada](https://evil.com)", "@octocat", "Ada https://evil.com", "<b>Ada</b>", "`Ada`", "Ada_Example",
                   "www.evil.com", "Ada evil.com", "Ada of Evil.Co.Uk"):   # a host shape is autolinked by GitHub
        assert "no mention, link or markup" in run(issue_body(credit=credit))[2], credit
    assert run(issue_body(credit="José O'Brien-Łukasz Jr.,  3rd"))[0] == 0
    assert run(issue_body(sample=CLEAN_SKILL, credit="J.R.R. Tolkien, A.B. Smith"))[0] == 0


def test_the_script_never_imports_a_network_module():
    text = (SCRIPTS / "add_community_case.py").read_text(encoding="utf-8") + (SCRIPTS / "community_corpus.py").read_text(encoding="utf-8")
    for name in ("socket", "urllib", "http.client", "requests", "ssl", "subprocess"):
        assert f"import {name}" not in text and f"from {name}" not in text, name
