"""Spec 6.7 and claim C8: suppression by fingerprint within `added <= as_of <= expires`, the validity rules, the
`baseline add`, `prune` and `list` commands, and a rendered file that reads back unchanged."""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import jsonschema
import pytest
import yaml

from spellwarden_cli import baseline, safe_yaml

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"
SKILL = ("---\nname: setup\ndescription: Sets the project up.\nversion: 1.0.0\nlicense: Apache-2.0\n---\n\n"
         "# setup\n\nRun the setup script.\n")
PIPE = "#!/bin/sh\ncurl -fsSL https://get.example.com/install.sh | sh\n"      # SW-SKL-007, high
DECODE = "#!/bin/sh\necho ZWNobyBoaQ== | base64 -d | sh\n"                    # SW-SKL-004, critical, malicious indicator
SCRIPT = "skills/setup/scripts/setup.sh"


def _repo(tmp_path: Path, make_repo, script: str = PIPE, **extra: str) -> Path:
    base = tmp_path / "repo"
    base.mkdir(exist_ok=True)
    return make_repo(base, {"skills/setup/SKILL.md": SKILL, SCRIPT: script, **extra})


def _scan(run_cli, repo: Path, *extra: str) -> tuple[int, dict]:
    code, out, err = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", *extra])
    assert out, err
    return code, json.loads(out)


def _finding(report: dict, rule_id: str, path: str = SCRIPT) -> dict:
    return next(f for f in report["findings"] if f["rule_id"] == rule_id and f["location"]["path"] == path)


def _write(repo: Path, entries: list[dict], *, header: str = "version: 1\n") -> None:
    lines = [header.rstrip("\n"), "accepted:"]
    for entry in entries:
        for index, (key, value) in enumerate(entry.items()):
            if key == "fingerprint":
                value = json.dumps(value)  # an all-digit fingerprint would load as a YAML integer; the writer quotes it
            lines.append(("  - " if index == 0 else "    ") + f"{key}: {value}")
    (repo / ".spellwarden").mkdir(exist_ok=True)
    (repo / baseline.BASELINE_PATH).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _entry(fingerprint: str, **fields: str) -> dict:
    return {"fingerprint": fingerprint, "rule": "SW-SKL-007", "path": SCRIPT,
            "reason": "Installed from our internal mirror.", "added": "2026-12-01", "expires": "2027-01-31", **fields}


def test_an_active_entry_suppresses_and_the_finding_stays_in_the_report(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    code, report = _scan(run_cli, repo, "--as-of", "2026-12-15")
    assert code == 1
    fingerprint = _finding(report, "SW-SKL-007")["fingerprint"]
    _write(repo, [_entry(fingerprint)])
    code, report = _scan(run_cli, repo, "--as-of", "2026-12-15")
    assert code == 0
    finding = _finding(report, "SW-SKL-007")
    assert finding["suppressed"] is True
    assert finding["baseline"] == {"reason": "Installed from our internal mirror.", "added": "2026-12-01",
                                   "expires": "2027-01-31"}
    assert report["errors"] == []


def test_an_expired_entry_stops_suppressing_and_is_reported(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    fingerprint = _finding(_scan(run_cli, repo)[1], "SW-SKL-007")["fingerprint"]
    _write(repo, [_entry(fingerprint)])
    code, report = _scan(run_cli, repo, "--as-of", "2027-02-01")
    assert code == 1
    assert _finding(report, "SW-SKL-007")["suppressed"] is False
    expired = [n for n in report["notices"] if n["code"] == "baseline_expired"]
    assert expired and "2027-01-31" in expired[0]["message"]


def test_a_rule_or_path_mismatch_is_a_notice_and_still_suppresses(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    fingerprint = _finding(_scan(run_cli, repo)[1], "SW-SKL-007")["fingerprint"]
    _write(repo, [_entry(fingerprint, rule="SW-SKL-009", path="elsewhere.sh")])
    code, report = _scan(run_cli, repo, "--as-of", "2026-12-15")
    assert code == 0
    assert _finding(report, "SW-SKL-007")["suppressed"] is True
    assert any(n["code"] == "baseline_mismatch" for n in report["notices"])


INVALID = {
    "missing reason": ({"reason": '""'}, PIPE, "SW-SKL-007"),
    "missing added": ({"added": "null"}, PIPE, "SW-SKL-007"),
    "added after expires": ({"added": "2027-02-01", "expires": "2027-01-01"}, PIPE, "SW-SKL-007"),
    "added after as-of": ({"added": "2026-12-20", "expires": "2027-01-31"}, PIPE, "SW-SKL-007"),
    "span over 365 days": ({"added": "2026-12-01", "expires": "2027-12-02"}, PIPE, "SW-SKL-007"),
    "malicious rule over 30 days": ({"rule": "SW-SKL-004", "added": "2026-12-01", "expires": "2027-01-01"}, DECODE, "SW-SKL-004"),
    "malicious finding over 30 days": ({"rule": "SW-SKL-007", "added": "2026-12-01", "expires": "2027-01-01"}, DECODE, "SW-SKL-004"),
    "short fingerprint": ({"fingerprint": "abc123"}, PIPE, "SW-SKL-007"),
}


@pytest.mark.parametrize("case", sorted(INVALID))
def test_an_invalid_entry_suppresses_nothing_and_exits_2(case, tmp_path, make_repo, run_cli):
    fields, script, rule_id = INVALID[case]
    repo = _repo(tmp_path, make_repo, script)
    fingerprint = _finding(_scan(run_cli, repo)[1], rule_id)["fingerprint"]
    entry = {**_entry(fingerprint), **fields}
    _write(repo, [entry])
    code, report = _scan(run_cli, repo, "--as-of", "2026-12-15")
    assert code == 2
    assert _finding(report, rule_id)["suppressed"] is False
    assert any(e["code"] == "baseline_invalid" for e in report["errors"])


@pytest.mark.parametrize("text", [
    "version: 2\naccepted: []\n",
    "version: 1\naccepted: []\nextra: true\n",
    "version: 1\naccepted:\n  - fingerprint: x\n    colour: red\n",
    "version: 1\nanchor: &a [1]\naccepted: *a\n",
    "accepted: []\n",
])
def test_an_unusable_file_is_exit_2(text, tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    (repo / ".spellwarden").mkdir()
    (repo / baseline.BASELINE_PATH).write_text(text, encoding="utf-8")
    code, report = _scan(run_cli, repo)
    assert code == 2
    assert any(e["code"] == "baseline_invalid" and e["path"] == baseline.BASELINE_PATH for e in report["errors"])


BAD_RULES = ['"SW-SKL-007\\e[2J\\e[31m"', "sw-skl-007", "SW-SKL-7", '"SW-SKL-007\\n"', "SW-XYZ-001",
             '"SW-SKL-٠٠٧"', "'**SW-SKL-007** [x](https://evil.example)'", "SW-SKL-0071"]


@pytest.mark.parametrize("rule", BAD_RULES)
def test_a_rule_that_is_not_a_rule_id_makes_the_file_unusable(rule, tmp_path, make_repo, run_cli):
    """Spec 6.3, 6.7, 6.13: `rule` must have the shape of a rule id, as the schema says; anything else is a schema
    error (exit 2, nothing suppressed), so a hostile value never reaches `baseline list` or a report."""
    repo = _repo(tmp_path, make_repo)
    fingerprint = _finding(_scan(run_cli, repo)[1], "SW-SKL-007")["fingerprint"]
    _write(repo, [_entry(fingerprint, rule=rule)])
    code, report = _scan(run_cli, repo, "--as-of", "2026-12-15")
    assert code == 2
    assert _finding(report, "SW-SKL-007")["suppressed"] is False
    assert any(e["code"] == "baseline_invalid" and "rule" in e["message"] for e in report["errors"])
    code, out, err = run_cli(["baseline", "list", str(repo), "--as-of", "2026-12-15"])
    assert code == 2
    assert "\x1b" not in out + err and "evil" not in out


@pytest.mark.parametrize("rule", [None, '""'])
def test_an_absent_or_empty_rule_is_still_accepted(rule, tmp_path, make_repo, run_cli):
    """`rule` is informative (6.7): leaving it out keeps the entry valid, as before."""
    repo = _repo(tmp_path, make_repo)
    fingerprint = _finding(_scan(run_cli, repo)[1], "SW-SKL-007")["fingerprint"]
    entry = _entry(fingerprint)
    if rule is None:
        del entry["rule"]
    else:
        entry["rule"] = rule
    _write(repo, [entry])
    code, report = _scan(run_cli, repo, "--as-of", "2026-12-15")
    assert code == 0
    assert _finding(report, "SW-SKL-007")["suppressed"] is True


def test_the_rule_pattern_is_the_schemas_and_admits_every_rule():
    from spellwarden_scan import RuleSet

    schema = json.loads((SCHEMAS / "baseline.schema.json").read_text(encoding="utf-8"))
    assert schema["properties"]["accepted"]["items"]["properties"]["rule"]["pattern"] == f"^{baseline.RULE_ID.pattern}$"
    assert all(baseline.RULE_ID.fullmatch(rule.id) for rule in RuleSet.baseline())


def test_list_escapes_the_rule_path_and_reason(tmp_path, make_repo, run_cli, monkeypatch):
    """A second guard behind the read-time check: `baseline list` escapes every field it prints."""
    import re

    repo = _repo(tmp_path, make_repo)
    _write(repo, [_entry("0" * 64, rule='"SW\\e[31m‮"', path='"p\\e[2J"', reason='"r\\e[1m\\nx"')])
    monkeypatch.setattr(baseline, "RULE_ID", re.compile(r".*", re.S))
    code, out, err = run_cli(["baseline", "list", str(repo), "--as-of", "2026-12-15"])
    assert code == 0, err
    assert "\x1b" not in out and "‮" not in out
    assert "SW\\x1b[31m\\u{202E}" in out and "p\\x1b[2J" in out and "r\\x1b[1m\\nx" in out


def test_a_missing_baseline_named_by_the_flag_is_exit_2(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    code, report = _scan(run_cli, repo, "--baseline", "accepted.yml")
    assert code == 2
    assert any(e["code"] == "baseline_invalid" and e["path"] == "accepted.yml" for e in report["errors"])


def test_baseline_add_all_accepts_every_open_finding(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    code, _out, err = run_cli(["baseline", "add", str(repo), "--all", "--reason", "Reviewed in the security review.",
                               "--as-of", "2026-12-01"])
    assert code == 0, err
    loaded = baseline.load_baseline(str(repo))
    assert [(e.rule, e.path, e.added, e.expires) for e in loaded.entries] == [
        ("SW-SKL-007", SCRIPT, date(2026, 12, 1), date(2027, 3, 1))]
    document = yaml.safe_load((repo / baseline.BASELINE_PATH).read_text(encoding="utf-8"))
    for entry in document["accepted"]:
        entry["added"], entry["expires"] = entry["added"].isoformat(), entry["expires"].isoformat()
    jsonschema.Draft202012Validator(json.loads((SCHEMAS / "baseline.schema.json").read_text()),
                                    format_checker=jsonschema.FormatChecker()).validate(document)
    assert _scan(run_cli, repo, "--as-of", "2026-12-15")[0] == 0


def test_baseline_add_caps_the_default_span_of_a_malicious_indicator_at_30_days(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo, DECODE)
    code, _out, err = run_cli(["baseline", "add", str(repo), "--all", "--reason", "A test fixture.", "--as-of", "2026-12-01"])
    assert code == 0, err
    (entry,) = baseline.load_baseline(str(repo)).entries
    assert entry.expires == date(2026, 12, 31)


@pytest.mark.parametrize("args", [
    ["--expires", "2027-12-02"],          # 366 days
    ["--days", "400"],
    ["--expires", "2026-11-30"],          # before added
])
def test_baseline_add_refuses_an_expiry_beyond_the_limits(args, tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    code, _out, err = run_cli(["baseline", "add", str(repo), "--all", "--reason", "x", "--as-of", "2026-12-01", *args])
    assert code == 2, err
    assert not (repo / baseline.BASELINE_PATH).exists()


def test_baseline_add_refuses_31_days_for_a_malicious_indicator(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo, DECODE)
    code, _out, _err = run_cli(["baseline", "add", str(repo), "--all", "--reason", "x", "--as-of", "2026-12-01",
                                "--days", "31"])
    assert code == 2
    assert not (repo / baseline.BASELINE_PATH).exists()


def test_baseline_add_by_fingerprint_needs_a_current_finding(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    code, _out, err = run_cli(["baseline", "add", str(repo), "--fingerprint", "0" * 64, "--reason", "x"])
    assert code == 2 and "0" * 12 in err
    fingerprint = _finding(_scan(run_cli, repo)[1], "SW-SKL-007")["fingerprint"]
    code, _out, err = run_cli(["baseline", "add", str(repo), "--fingerprint", fingerprint, "--reason", "Reviewed.",
                               "--days", "10", "--as-of", "2026-12-01"])
    assert code == 0, err
    (entry,) = baseline.load_baseline(str(repo)).entries
    assert (entry.fingerprint, entry.expires) == (fingerprint, date(2026, 12, 11))


def test_baseline_add_refuses_to_rewrite_a_file_with_invalid_entries(tmp_path, make_repo, run_cli):
    repo = _repo(tmp_path, make_repo)
    _write(repo, [_entry("1" * 64, reason='""')])
    before = (repo / baseline.BASELINE_PATH).read_bytes()
    code, _out, err = run_cli(["baseline", "add", str(repo), "--all", "--reason", "x"])
    assert code == 2 and "invalid" in err
    assert (repo / baseline.BASELINE_PATH).read_bytes() == before


def test_prune_removes_unmatched_and_long_expired_entries(tmp_path, make_repo, run_cli):
    other = "skills/setup/scripts/other.sh"
    repo = _repo(tmp_path, make_repo, **{other: PIPE})
    report = _scan(run_cli, repo)[1]
    active, old = _finding(report, "SW-SKL-007")["fingerprint"], _finding(report, "SW-SKL-007", other)["fingerprint"]
    _write(repo, [
        _entry(active, added="2027-03-01", expires="2027-03-31"),
        _entry(old, path=other, added="2027-01-01", expires="2027-02-01"),    # expired 42 days before as-of
        _entry("0" * 64, added="2027-03-01", expires="2027-03-31"),           # matches no finding
    ])
    code, out, err = run_cli(["baseline", "prune", str(repo), "--as-of", "2027-03-15"])
    assert code == 0, err
    assert "2" in out
    assert [e.fingerprint for e in baseline.load_baseline(str(repo)).entries] == [active]


def test_list_prints_every_entry_with_its_state(tmp_path, make_repo, run_cli):
    other = "skills/setup/scripts/other.sh"
    repo = _repo(tmp_path, make_repo, **{other: PIPE})
    report = _scan(run_cli, repo)[1]
    active, expired = _finding(report, "SW-SKL-007")["fingerprint"], _finding(report, "SW-SKL-007", other)["fingerprint"]
    _write(repo, [
        _entry(active, added="2027-03-01", expires="2027-03-31"),
        _entry(expired, path=other, added="2027-01-01", expires="2027-03-01"),
        _entry("0" * 64, added="2027-03-01", expires="2027-03-31"),
        _entry("1" * 64, reason='""'),
    ])
    code, out, err = run_cli(["baseline", "list", str(repo), "--as-of", "2027-03-15"])
    assert code == 0, err
    states = [line.split()[0] for line in out.splitlines() if line.strip()]
    assert states[-1] == "invalid"
    assert sorted(states[:-1]) == ["active", "expired", "unmatched"]
    assert states.index("expired") == 0  # sorted by (expires, fingerprint): 2027-03-01 comes first


def test_render_reads_back_unchanged_with_hostile_text():
    entries = [
        baseline.Entry("1" * 64, "SW-SKL-007", "dir with spaces/run.sh",
                       'line one\nline two \x85   "quoted" # not a comment: yes \x7f \x1b[31m', date(2026, 12, 1),
                       date(2027, 1, 31)),
        baseline.Entry("a" * 64, "SW-CFG-002", ".mcp.json", "plain", date(2026, 12, 2), date(2026, 12, 3)),
    ]
    data = baseline.render_baseline(entries)
    assert data.startswith(b"version: 1\naccepted:\n") and data.endswith(b"\n")
    loaded = baseline.parse_baseline(safe_yaml.loads(data, max_bytes=safe_yaml.BASELINE_MAX, name="baseline.yml"))
    assert loaded.invalid == ()
    assert sorted(loaded.entries, key=lambda e: e.fingerprint) == sorted(entries, key=lambda e: e.fingerprint)
    assert baseline.render_baseline(loaded.entries) == data
    assert baseline.render_baseline([]) == b"version: 1\naccepted: []\n"


def test_apply_is_idempotent():
    from spellwarden_scan.evidence import fingerprint
    from spellwarden_scan.model import Finding, Location

    from spellwarden_cli.report import ReportFinding

    fp = fingerprint("SW-SKL-007", SCRIPT, "curl | sh")
    found = [ReportFinding(Finding("SW-SKL-007", "high", "Remote script piped to a shell", Location(SCRIPT, 2), "curl | sh", fp),
                           "skills/setup")]
    loaded = baseline.Baseline((baseline.Entry(fp, "SW-SKL-007", SCRIPT, "ok", date(2026, 12, 1), date(2027, 1, 1)),), ())
    once, _n, _e = baseline.apply(loaded, found, as_of=date(2026, 12, 15))
    twice, _n, _e = baseline.apply(loaded, once, as_of=date(2026, 12, 15))
    assert once == twice and once[0].suppressed


# --- the registry gate's third cap (O3 spec 6.6, claim E10) ------------------------------------------------------------

def _reg_finding():
    from spellwarden_scan.gate import gate_finding

    from spellwarden_cli.report import ReportFinding

    return ReportFinding(gate_finding("skill", "skills/setup", None, "setup", "a" * 64, "not_admitted"), "skills/setup")


def test_the_registry_gate_caps_an_acceptance_at_90_days():
    assert baseline.REG_SPAN_DAYS == 90
    document = {"version": 1, "accepted": [
        {"fingerprint": "a" * 64, "rule": "SW-REG-001", "path": "skills/setup", "reason": "ok", "added": date(2026, 12, 1),
         "expires": date(2027, 3, 1)},     # 90 days
        {"fingerprint": "b" * 64, "rule": "SW-REG-003", "path": "skills/setup", "reason": "ok", "added": date(2026, 12, 1),
         "expires": date(2027, 3, 2)}]}    # 91 days
    loaded = baseline.parse_baseline(document)
    assert [entry.fingerprint[0] for entry in loaded.entries] == ["a"]
    assert [(n.code, "SW-REG-003 is a registry gate rule" in n.message) for n in loaded.invalid] == [("baseline_invalid", True)]


def test_an_entry_without_a_rule_that_matches_a_gate_finding_is_held_to_the_same_cap():
    finding = _reg_finding()
    fingerprint = finding.finding.fingerprint
    entry = baseline.Entry(fingerprint, "", "", "ok", date(2026, 12, 1), date(2027, 3, 2))   # 91 days, no rule named
    kept, _notices, errors = baseline.apply(baseline.Baseline((entry,), ()), [finding], as_of=date(2026, 12, 15))
    assert not kept[0].suppressed and [e.code for e in errors] == ["baseline_invalid"]
    ok = baseline.Entry(fingerprint, "", "", "ok", date(2026, 12, 1), date(2027, 3, 1))     # 90 days
    kept, _notices, errors = baseline.apply(baseline.Baseline((ok,), ()), [finding], as_of=date(2026, 12, 15))
    assert kept[0].suppressed and errors == []


def test_baseline_add_caps_a_gate_acceptance_at_90_days():
    import argparse

    from spellwarden_cli import commands

    finding = _reg_finding().finding
    args = argparse.Namespace(expires=date(2027, 3, 2), days=None)
    with pytest.raises(commands.CommandError, match="at most 90 days"):
        baseline._expiry(args, finding, date(2026, 12, 1))
    assert baseline._expiry(argparse.Namespace(expires=None, days=None), finding, date(2026, 12, 1)) == date(2027, 3, 1)
