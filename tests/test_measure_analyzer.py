"""Phase 4 batch B spec 11.6 and claim E-11: `scripts/measure_analyzer.py` runs one `claude -p` call per sample of the chosen
half through the product's `build_request` and `parse_reply`, prints counts and rates with 95% intervals only (never a sample's
text or a model's answer), writes its rows outside the repository, and refuses a sample whose hash is not the manifest's. The
`claude` here is a fake the test puts first on PATH; no model is called. The script is not part of the wheel."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tomllib
from pathlib import Path

import pytest

from spellwarden_scan import analyzer

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("measure_analyzer", ROOT / "scripts" / "measure_analyzer.py")
measure = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(measure)

SAMPLE_TEXT = "UNIQUE-SAMPLE-TEXT"
ANSWER_TEXT = "UNIQUE-ANSWER-TEXT"
FAKE_CLAUDE = r'''import json, os, re, sys
with open(os.environ["FAKE_CLAUDE_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
if os.listdir("."):
    sys.exit(3)  # the script runs claude in a new empty directory: a call from anywhere else fails here
user = sys.stdin.read()
if "NO-VERDICT-MARKER" in user:
    print("No issue.")
    sys.exit(0)
nonce = re.search(r"The nonce is ([0-9a-f]+)\.", user).group(1)
names = ["instruction_override", "data_exfiltration", "credential_access", "destructive_action", "remote_code", "obfuscation",
         "deceptive_description", "excessive_permission"]
issue = "MALICIOUS-MARKER" in user
categories = [{"id": name, "verdict": "issue" if issue and name == "remote_code" else "none",
               "confidence": "high" if issue else "low", "summary": "UNIQUE-ANSWER-TEXT", "spans": []} for name in names]
print(json.dumps({"nonce": nonce, "categories": categories}))
'''


def write_sample(base: Path, name: str, body: str) -> Path:
    directory = base / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(f"---\nname: {name}\ndescription: d\n---\n\n{body}\n{SAMPLE_TEXT}\n", encoding="utf-8")
    return directory


@pytest.fixture
def setup(tmp_path, monkeypatch):
    samples = tmp_path / "samples"
    rows = []
    for name, label, half, body in (("m1", "malicious", "held-out", "MALICIOUS-MARKER"),
                                    ("m2", "malicious", "held-out", "NO-VERDICT-MARKER"),
                                    ("b1", "benign", "held-out", "Formats code."),
                                    ("b2", "benign", "tuning", "Lists files.")):
        directory = write_sample(samples, name, body)
        files, _ = measure.read_sample(directory)
        rows.append({"id": name, "label": label, "half": half, "path": name, "package_sha256": measure.sample_hash(files),
                     "source": f"https://example.com/{name}"})
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"manifest": 1, "samples": rows}), encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    claude = bin_dir / "claude"
    claude.write_text(f"#!{sys.executable}\n{FAKE_CLAUDE}", encoding="utf-8")
    claude.chmod(0o755)
    log = tmp_path / "claude.log"
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_CLAUDE_LOG", str(log))
    return {"samples": samples, "manifest": manifest, "log": log, "out": tmp_path / "out"}


def argv(setup, half="held-out") -> list[str]:
    return ["--manifest", str(setup["manifest"]), "--samples", str(setup["samples"]), "--half", half, "--model",
            "claude-sonnet-5-5", "--out", str(setup["out"])]


@pytest.mark.skipif(sys.platform == "win32", reason="the fake claude is a script with a shebang line; the measurement runs on "
                                                     "Linux")
def test_one_call_per_sample_of_the_half_and_counts_only(setup, capsys):
    assert measure.main(argv(setup)) == 0
    out, err = capsys.readouterr()
    calls = [json.loads(line) for line in setup["log"].read_text(encoding="utf-8").splitlines()]
    assert len(calls) == 3  # the held-out half only
    assert all(call[:2] == ["-p", "--model"] and call[2] == "claude-sonnet-5-5" for call in calls)
    assert all(call[call.index("--tools") + 1] == "" and call[call.index("--system-prompt") + 1] == analyzer.SYSTEM
               for call in calls)
    # a sample is hostile data: no MCP server of the user's configuration and no saved session either
    assert all("--strict-mcp-config" in call and "--no-session-persistence" in call for call in calls)
    assert "detection rate 0.500 (1 of 2), 95% interval" in out
    assert "false-positive rate 0.000 (0 of 1), 95% interval" in out
    assert "analysed 2, no verdict 1, not read whole 0, failed calls 0" in out
    rows = [json.loads(line) for line in (setup["out"] / "rows.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [(row["id"], row["status"], row["found"]) for row in rows] == [
        ("m1", "analyzed", ["remote_code"]), ("m2", "no_verdict", []), ("b1", "analyzed", [])]
    summary = json.loads((setup["out"] / "summary.json").read_text(encoding="utf-8"))
    assert set(summary["entry"]) == set(analyzer.MEASURED_ENTRY_KEYS) and summary["entry"]["held_out_size"] == 3
    written = out + err + (setup["out"] / "rows.jsonl").read_text(encoding="utf-8") + json.dumps(summary)
    assert SAMPLE_TEXT not in written and ANSWER_TEXT not in written and "MALICIOUS-MARKER" not in written


def test_a_sample_that_changed_is_refused_before_any_call(setup, capsys):
    """b1 is the last sample of the half: the whole half is checked first, so no call was made for m1 and m2. The check
    needs no `claude`, so this test runs on Windows too, where the fake (a file without an extension) is not found."""
    (setup["samples"] / "b1" / "SKILL.md").write_text("changed\n", encoding="utf-8")
    assert measure.main(argv(setup)) == 2
    assert "sample b1 changed" in capsys.readouterr().err
    assert not setup["log"].exists() and not setup["out"].exists()


def test_the_rows_never_go_into_the_repository(setup, capsys):
    inside = argv(setup)
    inside[inside.index("--out") + 1] = str(ROOT / "measurement-out")
    assert measure.main(inside) == 2
    assert "--out must be outside this repository" in capsys.readouterr().err
    assert not (ROOT / "measurement-out").exists()


@pytest.mark.parametrize("change, words", [
    (lambda doc: doc.update(manifest=2), "must be"),
    (lambda doc: doc["samples"][0].update(label="unknown"), "label must be"),
    (lambda doc: doc["samples"][1].update(id=doc["samples"][0]["id"]), "repeated"),
    (lambda doc: doc["samples"][0].update(path="../x"), "path must be relative"),
    (lambda doc: doc["samples"][0].update(package_sha256="ABC"), "package_sha256"),
])
def test_a_malformed_manifest_is_refused(setup, change, words):
    document = json.loads(setup["manifest"].read_text(encoding="utf-8"))
    change(document)
    setup["manifest"].write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(measure.ManifestError, match=words):
        measure.load_manifest(setup["manifest"])


def test_the_wilson_interval():
    assert measure.wilson(0, 0) == (0.0, 1.0)
    low, high = measure.wilson(5, 10)
    assert round(low, 4) == 0.2366 and round(high, 4) == 0.7634
    assert measure.wilson(10, 10)[1] == pytest.approx(1.0) and measure.wilson(0, 10)[0] == pytest.approx(0.0)


def test_the_script_is_not_in_the_wheel_or_the_sdist():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["hatch"]["build"]["targets"]
    assert config["wheel"]["packages"] == ["src/spellwarden_scan", "src/spellwarden_cli"]
    assert not any(entry.startswith("scripts") for entry in config["sdist"]["include"])
