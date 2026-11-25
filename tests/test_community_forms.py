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
