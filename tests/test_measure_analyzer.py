"""Phase 4 batch B spec 11.6 and claim E-11: `scripts/measure_analyzer.py` runs one `claude -p` call per sample of the chosen
half through the product's `build_request` and `parse_reply`, prints counts and rates with 95% intervals only (never a sample's
text or a model's answer), writes its rows outside the repository, and refuses a sample whose hash is not the manifest's. The
call is isolated (a stripped environment, no settings file, the system prompt from a file), its JSON output says which model
answered, a usage limit stops the run with exit 3, `--resume` continues it, and the summary reports per stratum and per unit.
The `claude` here is a fake the test puts first on PATH; no model is called. The script is not part of the wheel."""
from __future__ import annotations

import hashlib
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

MODEL = "claude-sonnet-5-5"
OTHER_MODEL = "claude-other-5-5"
SAMPLE_TEXT = "UNIQUE-SAMPLE-TEXT"
ANSWER_TEXT = "UNIQUE-ANSWER-TEXT"
# The fake prints the JSON object of `claude -p --output-format json`. It logs its argv, the NAMES of its environment
# variables, the sample it was given (the `name:` of the frontmatter) and the hash and mode of its system prompt file.
FAKE_CLAUDE = r'''import hashlib, json, os, re, sys
args = sys.argv[1:]
user = sys.stdin.read()
record = {"argv": args, "env": sorted(os.environ), "sample": (re.findall(r"name: ([A-Za-z0-9._-]+)", user) or [None])[0]}
if "--system-prompt-file" in args:
    prompt = args[args.index("--system-prompt-file") + 1]
    with open(prompt, "rb") as handle:
        record["prompt_sha256"] = hashlib.sha256(handle.read()).hexdigest()
    record["prompt_mode"] = os.stat(prompt).st_mode & 0o777
descriptor = os.open(os.environ["FAKE_CLAUDE_LOG"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
os.write(descriptor, (json.dumps(record) + "\n").encode("utf-8"))
os.close(descriptor)
if os.listdir("."):
    sys.exit(3)  # the script runs claude in a new empty directory: a call from anywhere else fails here
model = args[args.index("--model") + 1]


def usage(name, output):
    return {name: {"inputTokens": 100, "outputTokens": output, "cacheReadInputTokens": 10, "cacheCreationInputTokens": 5}}


def emit(text, error=False, models=None):
    print(json.dumps({"type": "result", "is_error": error, "result": text, "modelUsage": models or {}}))


for variable, text in (("FAKE_CLAUDE_FAIL_ON", "Internal server error"), ("FAKE_CLAUDE_LIMIT_ON", "You have hit your usage limit")):
    if os.environ.get(variable) and os.environ[variable] in user:
        emit(text, error=True)
        sys.exit(1)
if "NOT-JSON-MARKER" in user:
    print("plain text")
    sys.exit(0)
models = {**usage(model, 0), **usage("claude-other-5-5", 40)} if "OTHER-MODEL-MARKER" in user else usage(model, 40)
if "NO-VERDICT-MARKER" in user:
    emit("No issue.", models=models)
    sys.exit(0)
nonce = re.search(r"The nonce is ([0-9a-f]+)\.", user).group(1)
names = ["instruction_override", "data_exfiltration", "credential_access", "destructive_action", "remote_code", "obfuscation",
         "deceptive_description", "excessive_permission"]
issue = "MALICIOUS-MARKER" in user
marked = re.search(r"^ *([0-9]+)\| .*MALICIOUS-MARKER", user, re.M)
span = [{"path": "SKILL.md", "line": int(marked.group(1)), "text": "MALICIOUS-MARKER"}] if issue and marked else []
categories = [{"id": name, "verdict": "issue" if issue and name == "remote_code" else "none",
               "confidence": "high" if issue else "low", "summary": "UNIQUE-ANSWER-TEXT",
               "spans": span if issue and name == "remote_code" else []} for name in names]
emit(json.dumps({"nonce": nonce, "categories": categories}), models=models)
'''
DEFAULT_SET = (("m1", "malicious", "held-out", "MALICIOUS-MARKER"),
               ("m2", "malicious", "held-out", "NO-VERDICT-MARKER"),
               ("b1", "benign", "held-out", "Formats code."),
               ("b2", "benign", "tuning", "Lists files."))
# On Windows a file has no executable mode and `shutil.which` finds a file by an extension of PATHEXT only, so the fake (a
# script with a shebang line and no extension) is not found there (plan fold-in F3). The tests that need a call are skipped
# on Windows; every refusal is decided before `claude` is looked for, so those tests run there too.
needs_fake_claude = pytest.mark.skipif(sys.platform == "win32", reason="the fake claude is a script with a shebang line; the "
                                                                        "measurement runs on Linux")


def write_sample(base: Path, name: str, body: str) -> Path:
    directory = base / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(f"---\nname: {name}\ndescription: d\n---\n\n{body}\n{SAMPLE_TEXT}\n", encoding="utf-8")
    return directory


def write_set(setup: dict, specs, name: str = "set") -> None:
    """Writes the samples and the manifest of `specs` ((id, label, half, body[, extra members]), ...) under a new directory and
    points `setup` at them."""
    base = setup["tmp"] / name
    samples = base / "samples"
    rows = []
    for spec in specs:
        sample_id, label, half, body = spec[:4]
        directory = write_sample(samples, sample_id, body)
        files, _ = measure.read_sample(directory)
        rows.append({"id": sample_id, "label": label, "half": half, "path": sample_id,
                     "package_sha256": measure.sample_hash(files), "source": f"https://example.com/{sample_id}",
                     **(spec[4] if len(spec) > 4 else {})})
    manifest = base / "manifest.json"
    manifest.write_text(json.dumps({"manifest": 1, "samples": rows}), encoding="utf-8")
    setup.update(samples=samples, manifest=manifest)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    claude = bin_dir / "claude"
    claude.write_text(f"#!{sys.executable}\n{FAKE_CLAUDE}", encoding="utf-8")
    claude.chmod(0o755)
    log = tmp_path / "claude.log"
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_CLAUDE_LOG", str(log))
    for variable in ("FAKE_CLAUDE_FAIL_ON", "FAKE_CLAUDE_LIMIT_ON"):
        monkeypatch.delenv(variable, raising=False)
    result = {"tmp": tmp_path, "log": log, "out": tmp_path / "out"}
    write_set(result, DEFAULT_SET)
    return result


def argv(setup, *extra: str, half: str = "held-out", out: Path | None = None) -> list[str]:
    return ["--manifest", str(setup["manifest"]), "--samples", str(setup["samples"]), "--half", half, "--model", MODEL,
            "--out", str(out or setup["out"]), *extra]


def calls(setup) -> list[dict]:
    log = setup["log"]
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []


def rows(out: Path) -> list[dict]:
    return [json.loads(line) for line in (out / "rows.jsonl").read_text(encoding="utf-8").splitlines()]


def summary(out: Path) -> dict:
    return json.loads((out / "summary.json").read_text(encoding="utf-8"))


@needs_fake_claude
def test_one_call_per_sample_of_the_half_and_counts_only(setup, capsys):
    assert measure.main(argv(setup)) == 0
    out, err = capsys.readouterr()
    made = [call["argv"] for call in calls(setup)]
    assert len(made) == 3  # the held-out half only
    assert all(call[:2] == ["-p", "--model"] and call[2] == MODEL for call in made)
    assert all(call[call.index("--tools") + 1] == "" and call[call.index("--output-format") + 1] == "json" for call in made)
    # a sample is hostile data: no MCP server of the user's configuration and no saved session either
    assert all("--strict-mcp-config" in call and "--no-session-persistence" in call for call in made)
    assert "detection rate 0.500 (1 of 2), 95% interval" in out
    assert "false-positive rate 0.000 (0 of 1), 95% interval" in out
    assert "analysed 2, no verdict 1, not read whole 0, failed calls 0" in out
    assert "answered by another model: malicious 0, benign 0" in out
    written_rows = sorted(rows(setup["out"]), key=lambda row: row["id"])
    assert [(row["id"], row["status"], row["found"], row["served"]) for row in written_rows] == [
        ("b1", "analyzed", [], [MODEL]), ("m1", "analyzed", ["remote_code"], [MODEL]), ("m2", "no_verdict", [], [MODEL])]
    assert all(row["input_tokens"] == 115 and row["output_tokens"] == 40 for row in written_rows)
    result = summary(setup["out"])
    assert set(result["entry"]) == set(analyzer.MEASURED_ENTRY_KEYS) and result["entry"]["held_out_size"] == 3
    assert result["samples"] == 3 and result["items_with_a_call_without_answer"] == 1 and result["strata"] == {}
    written = out + err + (setup["out"] / "rows.jsonl").read_text(encoding="utf-8") + json.dumps(result)
    assert SAMPLE_TEXT not in written and ANSWER_TEXT not in written and "MALICIOUS-MARKER" not in written


def test_the_child_environment_has_no_key_and_no_cloud_provider():
    parent = {"PATH": "/bin", "HOME": "/home/u", "CLAUDE_CONFIG_DIR": "/home/u/.claude-x", "ANTHROPIC_API_KEY": "k",
              "ANTHROPIC_BASE_URL": "u", "AWS_PROFILE": "p", "AWS_REGION": "r", "CLAUDE_CODE_USE_BEDROCK": "1",
              "CLAUDE_CODE_X": "x", "CLAUDECODE": "1", "CLAUDE_EFFORT": "high", "CLAUDECODE_OTHER": "kept"}
    assert measure.child_environment(parent) == {"PATH": "/bin", "HOME": "/home/u", "CLAUDE_CONFIG_DIR": "/home/u/.claude-x",
                                                 "CLAUDECODE_OTHER": "kept"}


@needs_fake_claude
def test_the_call_is_isolated(setup, monkeypatch, capsys):
    for variable in ("ANTHROPIC_API_KEY", "AWS_PROFILE", "CLAUDE_CODE_X", "CLAUDECODE", "CLAUDE_EFFORT"):
        monkeypatch.setenv(variable, "set-by-the-parent")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(setup["tmp"] / "profile"))
    assert measure.main(argv(setup)) == 0
    capsys.readouterr()
    made = calls(setup)
    assert len(made) == 3
    for call in made:
        names = set(call["env"])
        assert not names & {"ANTHROPIC_API_KEY", "AWS_PROFILE", "CLAUDE_CODE_X", "CLAUDECODE", "CLAUDE_EFFORT"}
        assert {"PATH", "CLAUDE_CONFIG_DIR"} <= names
        command = call["argv"]
        assert command[command.index("--setting-sources") + 1] == ""
        assert "--system-prompt" not in command
        prompt = Path(command[command.index("--system-prompt-file") + 1])
        assert call["prompt_sha256"] == hashlib.sha256(analyzer.SYSTEM.encode("utf-8")).hexdigest()
        assert call["prompt_mode"] == 0o600
        assert not prompt.exists() and not prompt.parent.exists()  # the call's directory is removed after the call


def test_the_json_output_is_read():
    usage = {MODEL: {"inputTokens": 3, "outputTokens": 0, "cacheReadInputTokens": 2, "cacheCreationInputTokens": 1},
             OTHER_MODEL: {"inputTokens": 10, "outputTokens": 7, "cacheReadInputTokens": 0, "cacheCreationInputTokens": 0}}
    reply = measure.read_output(json.dumps({"is_error": False, "result": "text", "modelUsage": usage}), 0)
    assert (reply.text, reply.usage_limit, list(reply.served), reply.input_tokens, reply.output_tokens) == (
        "text", False, [OTHER_MODEL], 16, 7)
    assert measure.read_output("plain text", 0).text is None
    assert measure.read_output(json.dumps(["not", "an", "object"]), 0).text is None
    failed = measure.read_output(json.dumps({"is_error": True, "result": "Internal server error"}), 1)
    assert failed.text is None and not failed.usage_limit
    for message in ("Claude AI usage limit reached", "You are out of extra usage", "You've hit your limit",
                    "You have reached your session LIMIT", "Out of usage until 5pm"):
        limit = measure.read_output(json.dumps({"is_error": True, "result": message}), 1)
        assert limit.text is None and limit.usage_limit, message
    # an answer that only mentions a limit is an answer, not a stop
    assert not measure.read_output(json.dumps({"is_error": False, "result": "usage limit"}), 0).usage_limit


@needs_fake_claude
def test_a_reply_served_by_another_model_counts_and_is_counted(setup, capsys):
    write_set(setup, (("m1", "malicious", "held-out", "MALICIOUS-MARKER"),
                      ("m3", "malicious", "held-out", "MALICIOUS-MARKER OTHER-MODEL-MARKER"),
                      ("b1", "benign", "held-out", "Formats code.")), name="other")
    assert measure.main(argv(setup)) == 0
    out = capsys.readouterr().out
    assert "detection rate 1.000 (2 of 2)" in out
    assert "answered by another model: malicious 1, benign 0" in out
    by_id = {row["id"]: row for row in rows(setup["out"])}
    assert by_id["m3"]["served"] == [OTHER_MODEL] and by_id["m3"]["input_tokens"] == 230
    assert summary(setup["out"])["answered_by_other_model"] == {"malicious": 1, "benign": 0}


@needs_fake_claude
def test_a_usage_limit_stops_the_run_and_resume_continues_it(setup, monkeypatch, capsys):
    held_out = [sample for sample in measure.load_manifest(setup["manifest"]) if sample["half"] == "held-out"]
    first, second, _third = measure.call_order(held_out)
    bodies = {sample_id: body for sample_id, _label, _half, body in DEFAULT_SET}
    monkeypatch.setenv("FAKE_CLAUDE_LIMIT_ON", bodies[second["id"]])
    assert measure.main(argv(setup, "--workers", "1")) == 3
    out = capsys.readouterr().out
    assert "usage limit" in out and "--resume" in out
    assert [row["id"] for row in rows(setup["out"])] == [first["id"]]  # no row for the sample that hit the limit
    assert not (setup["out"] / "summary.json").exists() and len(calls(setup)) == 2
    monkeypatch.delenv("FAKE_CLAUDE_LIMIT_ON")
    assert measure.main(argv(setup, "--workers", "1", "--resume")) == 0
    out = capsys.readouterr().out
    assert len(calls(setup)) == 4  # the finished sample was not asked again
    assert [call["sample"] for call in calls(setup)][2:] == [second["id"], _third["id"]]
    assert sorted(row["id"] for row in rows(setup["out"])) == ["b1", "m1", "m2"]
    assert "detection rate 0.500 (1 of 2)" in out and summary(setup["out"])["samples"] == 3


@needs_fake_claude
def test_resume_tries_a_failed_call_again(setup, monkeypatch, capsys):
    monkeypatch.setenv("FAKE_CLAUDE_FAIL_ON", "Formats code.")
    assert measure.main(argv(setup)) == 0
    assert "failed calls 1" in capsys.readouterr().out
    assert summary(setup["out"])["counts"]["not_analyzed"] == 1
    monkeypatch.delenv("FAKE_CLAUDE_FAIL_ON")
    assert measure.main(argv(setup, "--resume")) == 0
    assert "analysed 2, no verdict 1, not read whole 0, failed calls 0" in capsys.readouterr().out
    assert [call["sample"] for call in calls(setup)][3:] == ["b1"]
    assert len(rows(setup["out"])) == 4  # the failed row stays; the summary reads the latest row of each sample
    assert summary(setup["out"])["counts"]["not_analyzed"] == 0


@needs_fake_claude
def test_output_that_is_not_the_json_object_is_a_failed_call(setup, capsys):
    write_set(setup, (("m1", "malicious", "held-out", "MALICIOUS-MARKER NOT-JSON-MARKER"),), name="plain")
    assert measure.main(argv(setup)) == 0
    assert "failed calls 1" in capsys.readouterr().out
    assert [(row["status"], row["reason"]) for row in rows(setup["out"])] == [("not_analyzed", "claude_failed")]


def test_a_second_run_without_resume_is_refused(setup, capsys):
    """Decided before `claude` is looked for, so this test runs on Windows too."""
    setup["out"].mkdir()
    (setup["out"] / "rows.jsonl").write_text("", encoding="utf-8")
    assert measure.main(argv(setup)) == 2
    assert "--resume" in capsys.readouterr().err
    assert not setup["log"].exists() and not (setup["out"] / "summary.json").exists()


def test_resume_refuses_rows_of_another_model(setup, capsys):
    setup["out"].mkdir()
    row = {"id": "m1", "label": "malicious", "model": OTHER_MODEL, "status": "analyzed", "found": []}
    (setup["out"] / "rows.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert measure.main(argv(setup, "--resume")) == 2
    assert "another model" in capsys.readouterr().err
    assert not setup["log"].exists()


@pytest.mark.parametrize("workers", ["0", "17", "x"])
def test_the_number_of_workers_is_bounded(setup, workers, capsys):
    with pytest.raises(SystemExit) as stopped:
        measure.main(argv(setup, "--workers", workers))
    assert stopped.value.code == 2 and "--workers" in capsys.readouterr().err


@needs_fake_claude
def test_workers_give_the_summary_of_one_worker_in_an_order_that_does_not_depend_on_the_label(setup, capsys):
    specs = [(f"s{index}", "malicious" if index % 2 else "benign", "held-out",
              "MALICIOUS-MARKER" if index % 3 == 0 else "Reads notes.", {"stratum": f"g{index % 2}"}) for index in range(10)]
    write_set(setup, specs, name="many")
    one, many = setup["tmp"] / "one", setup["tmp"] / "many-out"
    assert measure.main(argv(setup, "--workers", "1", out=one)) == 0
    order = [call["sample"] for call in calls(setup)]
    assert order == [sample["id"] for sample in measure.call_order(measure.load_manifest(setup["manifest"]))]
    assert order == sorted(order, key=lambda sample_id: hashlib.sha256(sample_id.encode("utf-8")).hexdigest())
    assert measure.main(argv(setup, "--workers", "8", out=many)) == 0
    capsys.readouterr()
    assert summary(one) == summary(many)
    assert sorted(rows(one), key=lambda row: row["id"]) == sorted(rows(many), key=lambda row: row["id"])


@needs_fake_claude
def test_strata_are_reported_one_line_each(setup, capsys):
    write_set(setup, (("m1", "malicious", "held-out", "MALICIOUS-MARKER", {"stratum": "typo"}),
                      ("m2", "malicious", "held-out", "NO-VERDICT-MARKER", {"stratum": "typo"}),
                      ("m4", "malicious", "held-out", "MALICIOUS-MARKER", {"stratum": "obfus"}),
                      ("b1", "benign", "held-out", "Formats code.", {"stratum": "popular"})), name="strata")
    assert measure.main(argv(setup)) == 0
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line.startswith("stratum ")]
    assert [line.split()[1] for line in lines] == ["obfus", "popular", "typo"]
    assert "stratum typo (malicious) 0.500 (1 of 2), 95% interval" in out
    strata = summary(setup["out"])["strata"]
    assert strata["typo"] == {"label": "malicious", "found": 1, "total": 2, "rate": 0.5,
                              "interval_95": [round(value, 4) for value in measure.wilson(1, 2)]}
    assert strata["popular"]["label"] == "benign" and strata["popular"]["found"] == 0
    assert strata["obfus"]["rate"] == 1.0


@needs_fake_claude
def test_the_samples_of_a_unit_are_one_item(setup, capsys):
    write_set(setup, (("m1", "malicious", "held-out", "MALICIOUS-MARKER", {"unit": "pkg"}),
                      ("m5", "malicious", "held-out", "Reads notes.", {"unit": "pkg"}),
                      ("m2", "malicious", "held-out", "NO-VERDICT-MARKER", {"unit": "pkg2"}),
                      ("m6", "malicious", "held-out", "MALICIOUS-MARKER", {"unit": "pkg2"}),
                      ("b1", "benign", "held-out", "Formats code.")), name="units")
    assert measure.main(argv(setup)) == 0
    out = capsys.readouterr().out
    assert "detection rate 1.000 (2 of 2)" in out and "false-positive rate 0.000 (0 of 1)" in out
    assert "analysed 4, no verdict 1, not read whole 0, failed calls 0" in out  # the counts stay per call
    result = summary(setup["out"])
    assert result["samples"] == 3 and result["entry"]["held_out_size"] == 3
    assert result["items_with_a_call_without_answer"] == 1
    assert result["detection_rate"]["found"] == 2 and result["detection_rate"]["total"] == 2
    assert len(calls(setup)) == 5


def test_a_sample_that_changed_is_refused_before_any_call(setup, capsys):
    """b1 is a sample of the half: the whole half is checked first, so no call was made for m1 and m2. The check needs no
    `claude`, so this test runs on Windows too, where the fake (a file without an extension) is not found."""
    (setup["samples"] / "b1" / "SKILL.md").write_text("changed\n", encoding="utf-8")
    assert measure.main(argv(setup)) == 2
    assert "sample b1 changed" in capsys.readouterr().err
    assert not setup["log"].exists() and not setup["out"].exists()


def test_the_rows_never_go_into_the_repository(setup, capsys):
    inside = argv(setup, out=ROOT / "measurement-out")
    assert measure.main(inside) == 2
    assert "--out must be outside this repository" in capsys.readouterr().err
    assert not (ROOT / "measurement-out").exists()


def _same(doc, first: int, second: int, **members) -> None:
    doc["samples"][first].update(members)
    doc["samples"][second].update(members)


@pytest.mark.parametrize("change, words", [
    (lambda doc: doc.update(manifest=2), "must be"),
    (lambda doc: doc["samples"][0].update(label="unknown"), "label must be"),
    (lambda doc: doc["samples"][1].update(id=doc["samples"][0]["id"]), "repeated"),
    (lambda doc: doc["samples"][0].update(path="../x"), "path must be relative"),
    (lambda doc: doc["samples"][0].update(package_sha256="ABC"), "package_sha256"),
    (lambda doc: doc["samples"][0].update(stratum="has space"), "stratum must be"),
    (lambda doc: doc["samples"][0].update(stratum="x" * 61), "stratum must be"),
    (lambda doc: doc["samples"][0].update(unit="a/b"), "unit must"),
    # m1 is malicious and b1 benign: one package cannot be both, and a stratum holds one label
    (lambda doc: _same(doc, 0, 2, unit="pkg"), "unit pkg"),
    (lambda doc: _same(doc, 2, 3, unit="pkg"), "unit pkg"),  # b1 is held-out and b2 tuning: a package is in one half
    (lambda doc: _same(doc, 0, 2, stratum="s"), "stratum s"),
    (lambda doc: (_same(doc, 0, 1, unit="pkg"), doc["samples"][0].update(stratum="s")), "unit pkg"),
])
def test_a_malformed_manifest_is_refused(setup, change, words):
    document = json.loads(setup["manifest"].read_text(encoding="utf-8"))
    change(document)
    setup["manifest"].write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(measure.ManifestError, match=words):
        measure.load_manifest(setup["manifest"])


def test_a_unit_and_a_stratum_that_agree_are_accepted(setup):
    document = json.loads(setup["manifest"].read_text(encoding="utf-8"))
    _same(document, 0, 1, unit="pkg", stratum="typo.squat-1")
    setup["manifest"].write_text(json.dumps(document), encoding="utf-8")
    assert [sample.get("unit") for sample in measure.load_manifest(setup["manifest"])] == ["pkg", "pkg", None, None]


def test_the_wilson_interval():
    assert measure.wilson(0, 0) == (0.0, 1.0)
    low, high = measure.wilson(5, 10)
    assert round(low, 4) == 0.2366 and round(high, 4) == 0.7634
    assert measure.wilson(10, 10)[1] == pytest.approx(1.0) and measure.wilson(0, 10)[0] == pytest.approx(0.0)


def test_the_script_is_not_in_the_wheel_or_the_sdist():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["hatch"]["build"]["targets"]
    assert config["wheel"]["packages"] == ["src/spellwarden_scan", "src/spellwarden_cli"]
    assert not any(entry.startswith("scripts") for entry in config["sdist"]["include"])
