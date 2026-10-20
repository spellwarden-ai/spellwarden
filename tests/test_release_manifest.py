"""Spec 7.3 and 7.5: the release manifest ties the PyPI files, the image digest and the two wrapper commits of
one version together. `scripts/release_manifest.py` drafts it in release.yml and fills it in manifest.yml."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import release_manifest as rm  # noqa: E402

WHEEL = "a" * 64
SDIST = "b" * 64
DIGEST = "sha256:" + "c" * 64


def test_draft_has_exactly_the_six_keys_and_null_commits():
    manifest = rm.draft("1.0.0", WHEEL, SDIST, DIGEST)
    assert sorted(manifest) == sorted(rm.FIELDS)
    assert manifest["action_commit"] is None and manifest["component_commit"] is None
    assert rm.validate(manifest) == []


def test_render_is_sorted_two_space_json_with_a_trailing_newline():
    text = rm.render(rm.draft("1.0.0", WHEEL, SDIST, DIGEST))
    assert text.endswith("}\n")
    assert json.loads(text) == rm.draft("1.0.0", WHEEL, SDIST, DIGEST)
    assert text.index('"action_commit"') < text.index('"version"')
    assert '\n  "image_digest"' in text


@pytest.mark.parametrize("field, value", [
    ("version", "1.0"), ("version", "v1.0.0"), ("wheel_sha256", "A" * 64), ("sdist_sha256", "b" * 63),
    ("image_digest", "c" * 64), ("action_commit", "d" * 39), ("component_commit", "not-a-sha"),
])
def test_validate_names_every_malformed_field(field, value):
    manifest = rm.draft("1.0.0", WHEEL, SDIST, DIGEST)
    manifest[field] = value
    problems = rm.validate(manifest)
    assert problems and field in problems[0]


def test_validate_refuses_missing_and_unknown_keys():
    manifest = rm.draft("1.0.0", WHEEL, SDIST, DIGEST)
    del manifest["sdist_sha256"]
    manifest["extra"] = 1
    problems = rm.validate(manifest)
    assert any("sdist_sha256" in p for p in problems) and any("extra" in p for p in problems)


def test_fill_sets_both_commits_and_keeps_the_rest():
    filled = rm.fill(rm.draft("1.0.0", WHEEL, SDIST, DIGEST), action_commit="d" * 40, component_commit="e" * 40)
    assert filled["action_commit"] == "d" * 40 and filled["component_commit"] == "e" * 40
    assert filled["wheel_sha256"] == WHEEL and rm.validate(filled) == []


def _pypi(wheel=WHEEL, sdist=SDIST):
    return {"urls": [
        {"filename": "spellwarden-1.0.0-py3-none-any.whl", "packagetype": "bdist_wheel", "digests": {"sha256": wheel}},
        {"filename": "spellwarden-1.0.0.tar.gz", "packagetype": "sdist", "digests": {"sha256": sdist}},
    ]}


def test_pypi_problems_is_empty_when_both_files_match():
    assert rm.pypi_problems(rm.draft("1.0.0", WHEEL, SDIST, DIGEST), _pypi()) == []


def test_pypi_problems_names_a_mismatched_or_missing_file():
    manifest = rm.draft("1.0.0", WHEEL, SDIST, DIGEST)
    assert "spellwarden-1.0.0-py3-none-any.whl" in rm.pypi_problems(manifest, _pypi(wheel="f" * 64))[0]
    assert "spellwarden-1.0.0.tar.gz" in rm.pypi_problems(manifest, {"urls": _pypi()["urls"][:1]})[0]


def test_changelog_section_is_the_body_under_the_version_heading():
    text = "# Changelog\n\n## 1.0.0 (2027-01-20)\n\nOne.\n\nTwo.\n\n## 0.3.0 (2026-12-10)\n\nOld.\n"
    assert rm.changelog_section(text, "1.0.0") == "One.\n\nTwo.\n"
    with pytest.raises(ValueError):
        rm.changelog_section(text, "9.9.9")


def test_the_command_line_drafts_fills_and_checks(tmp_path, capsys):
    assert rm.main(["draft", "--version", "1.0.0", "--wheel-sha256", WHEEL, "--sdist-sha256", SDIST,
                    "--image-digest", DIGEST]) == 0
    draft = tmp_path / "m.json"
    draft.write_text(capsys.readouterr().out)
    assert rm.main(["fill", str(draft), "--action-commit", "d" * 40, "--component-commit", "e" * 40]) == 0
    assert json.loads(capsys.readouterr().out)["component_commit"] == "e" * 40
    pypi = tmp_path / "pypi.json"
    pypi.write_text(json.dumps(_pypi(wheel="f" * 64)))
    assert rm.main(["check-pypi", str(draft), str(pypi)]) == 1
    assert rm.main(["get", str(draft), "image_digest"]) == 0
    assert capsys.readouterr().out.strip().endswith(DIGEST)
