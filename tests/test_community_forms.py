"""Community reports spec 11, claims F-1 to F-3, F-7 and F-9 (F-4 to F-6 follow in the documents' own section below): the three
issue forms and `config.yml` ask for what decisions 1 to 3 say, the script's label table equals the forms, and the new text is plain
English with campaign tags. `.github/` and the Markdown documents are not in an sdist, so this file skips there."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from community_cases import SCRIPTS, load_script

ROOT = Path(__file__).resolve().parents[1]
FORMS_DIR = ROOT / ".github" / "ISSUE_TEMPLATE"
if not FORMS_DIR.is_dir() or not SCRIPTS.is_dir():
    pytest.skip(".github/ and scripts/ are not in an sdist", allow_module_level=True)

add = load_script("add_community_case.py", "spellwarden_add_community_case_forms_test")
FORMS = ("false-positive", "missed-detection", "new-rule")
ADVISORY = "https://github.com/spellwarden-ai/spellwarden/security/advisories/new"
DISCUSSIONS = "https://github.com/spellwarden-ai/spellwarden/discussions"
CONSENT = ("I wrote this sample, or I am allowed to publish it, and I agree that it is published in this repository under the "
           "Apache License 2.0, the licence of the repository.")
ORIGINS = ["I wrote it", "Adapted from public content (give the link below)", "From a benchmark or test set"]
CREDIT = ("Reports are unpaid. If you want a credit, write the name as you want it printed. It is then named in the CHANGELOG and in "
          "the corpus record, both public. If you later ask, a maintainer removes it from both on the main branch; released "
          "packages and the repository's history still hold it. Leave it empty and you are not named.")
# 5.1: the common fields in their order, with the type and whether the form requires them
COMMON = [("versions", "input", True), ("command", "input", True), ("file", "input", True), ("sample", "textarea", True),
          ("more", "textarea", False), ("origin", "dropdown", True), ("source", "input", False), ("credit", "input", False),
          ("consent", "checkboxes", True)]
# 5.2: the statements that every form's first block carries, as sentences
STATEMENTS = [
    "Reports are unpaid. A reporter is credited by name only if they write one below; there is no payment, bounty or plan credit.",
    "An issue is public. Do not post a working attack, or a method that would help someone hide content from the scanner before a "
    "fix is released: use [private reporting](" + ADVISORY + ") instead.",
    "Replace every real host with `example.com`, `evil.example` or another name under `.example`, `.invalid` or `.test`, and every "
    "address with one of `192.0.2.0/24`.",
    "Replace every secret and token with a placeholder such as `REDACTED`, never a real or a realistic one.",
    "Keep the shape of the line that matters: a command that downloads and runs something stays a command that downloads and runs "
    "something, from `example.com`.",
    "Do not paste anything that runs by itself when opened.",
    "Samples from a benchmark or its test sets (MaliciousSkillBench, its held-out half, the Trail of Bits skills) are not accepted "
    "into the corpus, so that the test sets stay clean. Describe the technique in words instead.",
    "You get a first answer within five working days. A first answer is an acceptance, a request for more, or a written reason; it "
    "is not a promise of a fix date.",
]


def flat(text: str) -> str:
    return " ".join(text.split())


def load_form(name: str) -> dict:
    return yaml.safe_load((FORMS_DIR / f"{name}.yml").read_text(encoding="utf-8"))


def fields(name: str) -> dict[str, dict]:
    return {element["id"]: element for element in load_form(name)["body"] if "id" in element}


@pytest.mark.parametrize("name", FORMS)
def test_f1_every_form_has_the_common_fields_in_order_with_their_types_and_required_flags(name):
    body = fields(name)
    positions = []
    for field_id, kind, required in COMMON:
        element = body[field_id]
        assert element["type"] == kind, (name, field_id)
        if field_id == "consent":
            assert len(element["attributes"]["options"]) == 1 and element["attributes"]["options"][0]["required"] is True
        else:
            assert bool(element.get("validations", {}).get("required", False)) is required, (name, field_id)
        if kind == "textarea" and field_id in ("sample", "more"):
            assert element["attributes"]["render"] == "text"
        positions.append(list(body).index(field_id))
    assert positions == sorted(positions), f"{name}: the common fields are out of order"


@pytest.mark.parametrize("name", FORMS)
def test_f1_the_consent_origin_and_credit_texts_are_the_decided_ones(name):
    body = fields(name)
    assert body["consent"]["attributes"]["options"][0]["label"] == CONSENT
    assert body["origin"]["attributes"]["options"] == ORIGINS
    assert flat(body["credit"]["attributes"]["description"]) == CREDIT
    assert "`spellwarden version`" in body["versions"]["attributes"]["description"]


def test_f1_each_form_keeps_its_own_fields_and_the_old_ones_are_gone():
    assert {"rule", "why"} <= set(fields("false-positive"))
    assert {"expected"} <= set(fields("missed-detection"))
    assert {"detects", "content", "gap", "harmless"} <= set(fields("new-rule")) and "example" not in fields("new-rule")
    assert fields("false-positive")["rule"]["validations"]["required"] is True
    assert fields("missed-detection")["source"]["type"] == "input"


@pytest.mark.parametrize("name", FORMS)
def test_f2_the_first_block_of_every_form_carries_the_five_statements(name):
    first = next(element for element in load_form(name)["body"] if element["type"] == "markdown")
    text = flat(first["attributes"]["value"])
    for statement in STATEMENTS:
        assert statement in text, (name, statement)
    assert "`example.com`" in text and "`.invalid`" in text and "`192.0.2.0/24`" in text and "five working days" in text


def test_f2_the_first_block_is_the_same_wording_in_all_three_forms():
    blocks = [next(e for e in load_form(name)["body"] if e["type"] == "markdown")["attributes"]["value"] for name in FORMS]
    assert blocks[0] == blocks[1] == blocks[2]


def test_f3_the_chooser_turns_blank_issues_off_and_points_to_the_private_path_the_discussions_and_the_product():
    config = yaml.safe_load((FORMS_DIR / "config.yml").read_text(encoding="utf-8"))
    assert config["blank_issues_enabled"] is False
    links = config["contact_links"]
    assert [link["url"] for link in links] == [
        ADVISORY, DISCUSSIONS, "https://spellwarden.ai/docs?utm_source=github&utm_medium=issue-form&utm_campaign=issue-forms"]
    assert "Do not open a public issue" in links[0]["about"] and "security@spellwarden.ai" in links[0]["about"]
    assert "five working days" in links[0]["about"]
    assert "blob/main/SECURITY.md" not in (FORMS_DIR / "config.yml").read_text(encoding="utf-8")


def test_f9_the_label_table_of_the_script_equals_the_labels_of_the_three_forms():
    assert set(add.FORM_LABELS) == set(FORMS)
    for name in FORMS:
        body = fields(name)
        assert set(add.FORM_LABELS[name]) == {field_id for field_id, _kind, _required in COMMON}
        for field_id, label in add.FORM_LABELS[name].items():
            assert body[field_id]["attributes"]["label"] == label, (name, field_id)
    assert add.CONSENT_TEXT == CONSENT and list(add.ORIGIN_OPTIONS) == ORIGINS


@pytest.mark.parametrize("name", FORMS)
def test_f9_every_field_of_each_form_is_known_to_the_script_with_its_label_and_in_the_forms_order(name):
    """r1:F1: the parser reads every field GitHub renders, the ones the record does not keep included, in the form's order."""
    order = [element["id"] for element in load_form(name)["body"] if "id" in element]
    assert list(add.FIELD_ORDER[name]) == order
    body = fields(name)
    assert set(add.ALL_LABELS[name]) == set(order)
    for field_id, label in add.ALL_LABELS[name].items():
        assert body[field_id]["attributes"]["label"] == label, (name, field_id)


# --- F-7: plain text, campaign tags, the command that prints the version --------------------------------------------------------

TEXT_FILES = [".github/ISSUE_TEMPLATE/config.yml", ".github/ISSUE_TEMPLATE/false-positive.yml",
              ".github/ISSUE_TEMPLATE/missed-detection.yml", ".github/ISSUE_TEMPLATE/new-rule.yml", "SECURITY.md",
              "CONTRIBUTING.md", "ROADMAP.md", "fixtures/community/README.md", "benchmarks/README.md"]
TAGGED_FILES = [".github/ISSUE_TEMPLATE/config.yml", ".github/ISSUE_TEMPLATE/false-positive.yml",
                ".github/ISSUE_TEMPLATE/missed-detection.yml", ".github/ISSUE_TEMPLATE/new-rule.yml", "fixtures/community/README.md"]


@pytest.mark.parametrize("name", TEXT_FILES)
def test_f7_the_text_has_no_em_dash_no_en_dash_no_exclamation_mark_and_never_says_version_with_two_dashes(name):
    path = ROOT / name
    if not path.exists():
        pytest.skip(f"{name} is not in an sdist")
    text = path.read_text(encoding="utf-8")
    for character in ("\u2014", "\u2013", "!"):
        assert character not in text, (name, repr(character))
    assert "spellwarden --version" not in text


@pytest.mark.parametrize("name", TAGGED_FILES)
def test_f7_every_link_to_the_site_carries_the_three_campaign_tags(name):
    text = (ROOT / name).read_text(encoding="utf-8")
    links = re.findall(r"https://spellwarden\.ai[^\s)\"'>`]*", text)
    for link in links:
        for tag in ("utm_source=", "utm_medium=", "utm_campaign="):
            assert tag in link, (name, link)


# --- F-4 to F-6: the documents ----------------------------------------------------------------------------------------------------

CORPUS_SENTENCE = ("The community corpus in `fixtures/community/` is not a test set: it holds samples that people reported and rule "
                   "changes were made for, so it is never used for a claim about rates, and a sample of a test set is not accepted "
                   "into it.")


def read(name: str) -> str:
    path = ROOT / name
    if not path.exists():
        pytest.skip(f"{name} is not in an sdist")
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def section(text: str, heading: str, following: str) -> str:
    return flat(text[text.index(heading):text.index(following)])


def test_f4_the_security_policy_names_private_reporting_and_keeps_the_address_and_the_answer_time():
    text = flat(read("SECURITY.md"))
    assert "GitHub's private vulnerability reporting for this repository" in text and "\"Report a vulnerability\"" in text
    assert "Both reach the maintainers, and both get a first answer within five working days." in text
    assert "Send an email to `security@spellwarden.ai`. Do not open a public issue for a security problem." in text
    assert "You get a first answer within five working days." in text
    assert "Use private reporting or send it to `security@spellwarden.ai` instead when the sample is a working attack" in text
    assert "a bypass can join the public corpus of accepted samples in `fixtures/community/`, and only with your agreement in writing" in text
    assert "a public issue with a harmless sample is the right place for it: see [CONTRIBUTING.md](CONTRIBUTING.md)" in text


def test_f5_contributing_tells_a_reporter_what_the_forms_ask_and_what_happens_next():
    text = read("CONTRIBUTING.md")
    assert "## Report a false positive or a missed detection" not in text and "## Report a miss, a false alarm or a new pattern" in text
    report = section(text, "## Report a miss, a false alarm or a new pattern", "## Propose a rule")
    for needle in ("**False positive**", "**Missed detection**", "**New rule proposal**", "https://github.com/spellwarden-ai/spellwarden/issues/new/choose",
                   "`spellwarden version` prints both", "the Apache License 2.0, the licence of this repository", "Reports are unpaid.",
                   "only if you write a name in the form", "released packages and the history of the repository still hold it",
                   "goes to private reporting and not to an issue: see [SECURITY.md](SECURITY.md)", "within five working days",
                   "it is not a promise of a fix date", "`fixtures/community/`", "a written reason that names the rule",
                   "[Discussions](https://github.com/spellwarden-ai/spellwarden/discussions)",
                   "[how to handle false positives](https://spellwarden.ai/docs/false-positives?utm_source=github&utm_medium=readme&utm_campaign=contributing)",
                   "A sample that comes from a benchmark's test sets is not accepted"):
        assert needle in report, needle
    assert "[Propose a rule](#propose-a-rule)" in report and "## Propose a rule" in text


def test_f5_the_tuning_paragraph_ends_with_the_corpus_sentence_and_keeps_what_other_tests_read():
    text = read("CONTRIBUTING.md")
    paragraph = next(line for line in text.splitlines() if line.startswith("Keep the benchmark's test sets out of rule work."))
    assert paragraph.endswith(" " + CORPUS_SENTENCE)
    assert "does not cite, quote or add as a fixture any sample of a test set" in paragraph
    assert "samples people report. The same holds for the normalisation steps" in paragraph


def test_f6_the_roadmap_no_longer_lists_the_report_channel_as_next_and_lists_it_as_shipped():
    text = read("ROADMAP.md")
    assert "A way to report misses and false alarms" not in text
    shipped = section(text, "## Shipped\n", "## Being built now")
    assert "Anyone can report a miss, a false alarm or a new pattern with an issue form" in shipped
    assert "a working bypass goes to private reporting" in shipped and "`fixtures/community/`" in shipped
    assert "a thread per release in GitHub Discussions lists the rules that changed" in shipped
    assert "Since" not in shipped[shipped.index("Anyone can report"):]
    assert "A way to report" not in section(text, "## Next\n", "## Being considered")


def test_pull_request_template_points_at_the_rules():
    """P6-16's done-when: GitHub's community profile shows every file it checks for, the pull request template included."""
    text = flat((ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8"))
    for needle in ("CONTRIBUTING.md", "SECURITY.md", "make check", "One concern per pull request", "test set"):
        assert needle in text, needle
