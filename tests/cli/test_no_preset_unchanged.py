"""9.8 part 1 (E-10, E-6, E-7): within 1.18.0, for every fixture root, a scan without a preset, with `--preset balanced`, with
`preset: balanced` in a settings file (`--config`) and with SPELLWARDEN_PRESET=balanced writes the same bytes in every format, the HTML
report included, with the same exit code; the JSON report has no `preset` key, no `preset_from` and no notice `preset`; and the
HTML report is inert and holds every finding, notice and error of the JSON report. Part 2 (against 1.17.0) is
tests/test_golden_1_17_0.py; part 3: the golden repositories of 1.0.0 and 1.13.0 are fixture roots here, so `balanced` writes
what their own golden tests hold."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from html_checks import inert_problems, missing_from_html

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("record_1_17_0", ROOT / "tests" / "golden" / "record_1_17_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)
reports = record.reports


def _settings_file_with_balanced(repo: Path, directory: Path) -> Path:
    """A settings file outside the repository that holds the repository's own settings (when it has any) and `preset: balanced`,
    named with --config: a key written into the repository would add a file to a skill whose root is the repository root."""
    own = repo / ".spellwarden" / "config.yml"
    text = own.read_text(encoding="utf-8") if own.exists() else "version: 1\n"
    if not text.endswith("\n"):
        text += "\n"
    path = directory / "settings.yml"
    path.write_text(text + "preset: balanced\n", encoding="utf-8", newline="\n")
    return path


def test_the_golden_repositories_are_fixture_roots():
    assert {"tests/golden/1.0.0/repo", "tests/golden/1.13.0/repo", "fixtures/html-escape", "fixtures/presets"} <= set(
        record.scan_roots())


@pytest.mark.parametrize("root", record.scan_roots())
def test_no_preset_and_every_way_of_saying_balanced_write_the_same_bytes(root, tmp_path):
    repo = reports.build_repo(root, tmp_path / "repo")
    code, plain = reports.render(repo, tmp_path / "none", formats=reports.ALL_FORMATS)
    variants = {
        "flag": reports.render(repo, tmp_path / "flag", formats=reports.ALL_FORMATS, extra=("--preset", "balanced")),
        "environment": reports.render(repo, tmp_path / "environment", formats=reports.ALL_FORMATS,
                                      env={"SPELLWARDEN_PRESET": "balanced"}),
    }
    settings = _settings_file_with_balanced(repo, tmp_path)
    variants["file"] = reports.render(repo, tmp_path / "file", formats=reports.ALL_FORMATS, extra=("--config", str(settings)))
    for way, (other_code, outputs) in variants.items():
        assert other_code == code, way
        for fmt, _ in reports.ALL_FORMATS:
            assert outputs[fmt] == plain[fmt], f"{way}: {fmt}"
    document = json.loads(plain["json"])
    assert "preset" not in document
    assert all("preset_from" not in entry for entry in document["findings"])
    assert all(entry["code"] != "preset" for entry in document["notices"])
    html = plain["html"].decode("utf-8")
    assert inert_problems(html) == []
    assert missing_from_html(html, document) == []
