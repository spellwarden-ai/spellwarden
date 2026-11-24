"""Spec 7.4: the pre-release workflow's e2e jobs hold the checks the spec names."""
from __future__ import annotations

import re
from pathlib import Path

import yaml


def test_the_permissions_job_checks_the_failed_sarif_upload_warning():
    # Spec 7.4: with `contents: read` the Action emits sarif_upload_failed; a candidate that swallowed the failed
    # upload silently must not pass. The Action appends the code to $RUNNER_TEMP/spellwarden-annotations.txt.
    workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml")
                              .read_text(encoding="utf-8"))
    steps = workflow["jobs"]["e2e-permissions"]["steps"]
    checks = [s for s in steps if "sarif_upload_failed" in s.get("run", "") and "spellwarden-annotations.txt" in s.get("run", "")]
    assert len(checks) == 1, "one step reads the annotations file for sarif_upload_failed"
    assert "always()" in checks[0]["if"], "it runs even when the scan step failed"


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _steps(workflow: str, job: str) -> list[dict]:
    return yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))["jobs"][job]["steps"]


def test_nothing_is_published_that_the_build_job_did_not_hash():
    # Security review of the 1.0.0 build: publish and github-release upload the `dist` artifact; each checks first
    # that it holds exactly the wheel and the sdist whose SHA-256 the build job recorded.
    for job, upload in (("publish", "pypa/gh-action-pypi-publish@"), ("github-release", "gh release create")):
        steps = _steps("release.yml", job)
        check = next(i for i, s in enumerate(steps) if "sha256sum -c -" in s.get("run", ""))
        first_upload = next(i for i, s in enumerate(steps)
                            if str(s.get("uses", "")).startswith(upload) or upload in s.get("run", ""))
        assert check < first_upload, job
        assert "$WHEEL_SHA256" in steps[check]["run"] and "$SDIST_SHA256" in steps[check]["run"]


def test_the_manifest_is_attested_only_from_main():
    first = _steps("manifest.yml", "manifest")[0]
    assert 'if [ "$GITHUB_REF" != "refs/heads/main" ]' in first["run"] and "exit 1" in first["run"]


def test_the_manifest_trusts_only_the_allowed_signers():
    run = "\n".join(step.get("run", "") for step in _steps("manifest.yml", "manifest"))
    verifications = [line for line in run.splitlines() if " tag -v " in line]
    assert len(verifications) == 3
    assert all("gpg.ssh.allowedSignersFile=" in line and "gpg.minTrustLevel=fully" in line for line in verifications)


def test_the_permissions_job_gives_the_action_a_token_that_cannot_upload():
    # GitHub may accept a SARIF upload from a public repository's read-only token, so only an invalid token makes
    # the refusal certain (found on the Action's first pull request).
    scan = next(s for s in _steps("release.yml", "e2e-permissions") if s.get("id") == "scan")
    assert scan["with"]["token"] == "not-a-token" and scan["with"]["sarif-upload"] == "true"


def test_the_no_python_job_adds_no_python_to_the_path():
    # The v1.0.0 release run: e2e-setup's setup-python and setup-uv add their directories to $GITHUB_PATH, which the
    # runner puts in front of the Action step's own `env: PATH`, so the Action found Python and the case failed.
    steps = _steps("release.yml", "e2e-no-python")
    action = next(i for i, s in enumerate(steps) if s.get("uses") == "./.spellwarden-action")
    before = [str(s.get("uses", "")) for s in steps[:action]]
    assert not [u for u in before if u.startswith(("actions/setup-python@", "astral-sh/setup-uv@", "./.github/actions/e2e-setup"))]


# --- the connected e2e job (O3 plan P23, Task 11) -------------------------------------------------------------------------

def _release() -> dict:
    return yaml.safe_load((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))


def test_the_connected_e2e_job_runs_after_build_on_ubuntu_with_python_3_11_and_3_13():
    job = _release()["jobs"]["e2e-connected"]
    assert job["needs"] == "build" and job["runs-on"] == "ubuntu-latest"
    assert job["strategy"]["matrix"]["python"] == ["3.11", "3.13"] and job["strategy"]["fail-fast"] is False
    assert job["defaults"]["run"]["shell"] == "bash"


def test_nothing_is_published_before_the_connected_e2e_passes():
    jobs = _release()["jobs"]
    for name in ("publish", "image"):
        assert "e2e-connected" in jobs[name]["needs"], name


def test_the_connected_e2e_job_pins_every_action_by_commit_with_a_version_comment():
    text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    block = text[text.index("\n  e2e-connected:\n"):text.index("\n  publish:\n")]
    uses = [line for line in block.splitlines() if line.strip().startswith(("- uses:", "uses:"))]
    assert uses, "the job uses actions"
    for line in uses:
        assert re.search(r"uses: [\w./-]+@[0-9a-f]{40}  # v\d+\.\d+\.\d+$", line), line


def test_the_connected_e2e_job_scans_the_findings_repository_with_both_credentials_and_checks_each_recording():
    steps = _steps("release.yml", "e2e-connected")
    run = "\n".join(step.get("run", "") for step in steps)
    assert 'make_repo.py findings@connected' in run
    assert run.count("fixtures/ci/fake_api.py --script fixtures/ci/script.json --port 0 --record") == 2
    assert "check_connected.py" in run and "--credential oidc" in run and "--credential key" in run
    assert "SPELLWARDEN_ORG=acme" in run and "SPELLWARDEN_API_KEY=" in run and "SPELLWARDEN_API_URL=" in run
    assert "ACTIONS_ID_TOKEN_REQUEST_URL=" in run and "ACTIONS_ID_TOKEN_REQUEST_TOKEN=" in run
    # the scan sees only the environment it is given: the runner's own GITHUB_* values would otherwise win
    assert "env -i" in run
    # the wheel under test is the one the build job produced, installed without its own dependencies from the index
    assert any(step.get("uses", "").startswith("actions/download-artifact@") for step in steps)
    assert "--no-deps" in run and "--require-hashes" in run and "docker/requirements.deps.txt" in run
    # no credential-shaped literal is written in the workflow
    assert not re.search(r"sw[kctri]_[A-Za-z0-9_-]{40}", (WORKFLOWS / "release.yml").read_text(encoding="utf-8"))


def test_the_build_job_runs_the_node_checks_of_the_zuplo_guard_before_anything_is_published():
    # Review r0:F3 of the Zuplo export: `make check` is Python only, so a tag whose guard text breaks a Node vector would
    # publish. The build job, which every publishing job needs, runs `make check-node` on Node 24 after `make check`.
    steps = _steps("release.yml", "build")
    runs = [s.get("run", "") for s in steps]
    assert runs.index("make check-node") > runs.index("make check")
    node = [s for s in steps if str(s.get("uses", "")).startswith("actions/setup-node@")]
    assert len(node) == 1 and node[0]["with"]["node-version"] == "24"
    assert re.fullmatch(r"actions/setup-node@[0-9a-f]{40}", node[0]["uses"])
    assert node[0]["uses"] == next(s["uses"] for s in _steps("check.yml", "zuplo") if str(s.get("uses", "")).startswith("actions/setup-node@"))


# --- the gateway exports (1.15.0, phase 3 batch 2b spec 10.9) --------------------------------------------------------------

def test_the_gateway_exports_job_runs_both_gateways_on_linux_after_build():
    job = _release()["jobs"]["gateway-exports"]
    assert job["needs"] == "build" and job["runs-on"] == "ubuntu-latest"
    run = "\n".join(step.get("run", "") for step in job["steps"])
    assert 'tests/gateway_ci.py toolhive "$RUNNER_TEMP/toolhive"' in run
    assert 'tests/gateway_ci.py docker "$RUNNER_TEMP/docker" --capture "$RUNNER_TEMP/captured/docker-v0.44.3"' in run
    upload = [step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/upload-artifact@")]
    assert len(upload) == 1 and upload[0]["if"] == "always()" and upload[0]["with"]["name"] == "gateway-captures"


def test_nothing_is_published_before_the_gateway_exports_pass():
    jobs = _release()["jobs"]
    for name in ("publish", "image"):
        assert "gateway-exports" in jobs[name]["needs"], name


def test_the_gateway_exports_job_pins_every_action_by_commit_and_names_no_macos_runner():
    text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    block = text[text.index("\n  gateway-exports:\n"):text.index("\n  publish:\n")]
    uses = [line for line in block.splitlines() if line.strip().startswith(("- uses:", "uses:"))]
    assert len(uses) == 3
    for line in uses:
        assert re.search(r"uses: [\w./-]+@[0-9a-f]{40}  # v\d+\.\d+\.\d+$", line), line
    assert "macos" not in text


# --- the rule benchmark (Rule benchmark, section 11; claims T-20 and T-22) -----------------------------------------------------

PINNED = r"uses: [\w./-]+@[0-9a-f]{40}  # v\d+\.\d+\.\d+$"


def _uses_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip().startswith(("- uses:", "uses:"))]


def _run(steps: list[dict]) -> str:
    return "\n".join(step.get("run", "") for step in steps)


def test_the_rule_benchmark_job_runs_after_build_on_linux_and_windows():
    job = _release()["jobs"]["rule-benchmark"]
    assert job["needs"] == "build" and job["runs-on"] == "${{ matrix.os }}"
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "windows-latest"] and job["strategy"]["fail-fast"] is False
    assert job["defaults"]["run"]["shell"] == "bash" and job["timeout-minutes"] == 60
    assert job["env"] == {"VERSION": "${{ needs.build.outputs.version }}", "WHEEL_SHA256": "${{ needs.build.outputs.wheel_sha256 }}"}


def test_the_rule_benchmark_job_installs_the_hashed_wheel_and_measures_against_the_committed_entry():
    steps = _steps("release.yml", "rule-benchmark")
    install = next(step for step in steps if "pip install" in step.get("run", ""))
    run = install["run"]
    assert run.index("sha256sum -c -") < run.index("pip install"), "the wheel's hash is checked before anything is installed"
    assert "--require-hashes -r docker/requirements.deps.txt" in run and "--no-deps" in run
    assert "--require-hashes -r benchmarks/requirements.txt" in run
    assert any(str(step.get("uses", "")).startswith("actions/download-artifact@") for step in steps)
    measure = next(step for step in steps if "rule_benchmark.py run" in step.get("run", ""))
    assert '--expect-version "$VERSION"' in measure["run"] and "--verify benchmarks/results.json" in measure["run"]
    assert measure["env"] == {"GITHUB_TOKEN": "${{ github.token }}"} and "if" not in measure


def test_the_rule_benchmark_job_checks_the_history_and_writes_the_assets_on_linux_only():
    steps = _steps("release.yml", "rule-benchmark")
    history = next(step for step in steps if "check-history" in step.get("run", ""))
    render = next(step for step in steps if "rule_benchmark.py render" in step.get("run", ""))
    upload = next(step for step in steps if str(step.get("uses", "")).startswith("actions/upload-artifact@"))
    for step in (history, render, upload):
        assert step["if"] == "runner.os == 'Linux'"
    assert "--json-out" in render["run"] and "--markdown-out" in render["run"]
    assert upload["with"]["name"] == "rule-benchmark" and upload["with"]["if-no-files-found"] == "error"


def test_the_rule_benchmark_job_pins_its_four_actions_and_publishing_waits_for_it():
    text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    block = text[text.index("\n  rule-benchmark:\n"):text.index("\n  gateway-exports:\n")]
    uses = _uses_lines(block)
    assert len(uses) == 4
    for line in uses:
        assert re.search(PINNED, line), line
    jobs = _release()["jobs"]
    for name in ("publish", "image", "github-release"):
        assert "rule-benchmark" in jobs[name]["needs"], name
    assert jobs["publish"]["needs"].index("rule-benchmark") == jobs["publish"]["needs"].index("e2e-connected") + 1
    assert "macos" not in text


def test_the_github_release_attaches_the_two_assets_and_keeps_its_dist_check():
    steps = _steps("release.yml", "github-release")
    download = [step for step in steps if str(step.get("uses", "")).startswith("actions/download-artifact@")]
    assert [step["with"]["name"] for step in download] == ["dist", "rule-benchmark"]
    check = next(step for step in steps if "rule-benchmark.json rule-benchmark.md " in step.get("run", ""))
    create = next(step for step in steps if "gh release create" in step.get("run", ""))
    assert steps.index(check) < steps.index(create)
    assert '"$RUNNER_TEMP/rule-benchmark/rule-benchmark.json" "$RUNNER_TEMP/rule-benchmark/rule-benchmark.md"' in create["run"]
    dist = next(step for step in steps if "find dist -mindepth 1" in step.get("run", ""))
    assert '"spellwarden-${VERSION}-py3-none-any.whl spellwarden-${VERSION}.tar.gz "' in dist["run"]


def _rehearsal() -> dict:
    return yaml.safe_load((WORKFLOWS / "rule-benchmark.yml").read_text(encoding="utf-8"))


def test_the_rehearsal_starts_by_hand_only_with_a_verify_input_and_reads_only():
    document = _rehearsal()
    triggers = document.get("on", document.get(True))
    assert list(triggers) == ["workflow_dispatch"]
    assert triggers["workflow_dispatch"]["inputs"] == {"verify": {
        "description": "The numbers must equal the entry committed for this version in benchmarks/results.json",
        "required": False, "default": False, "type": "boolean"}}
    assert document["permissions"] == {"contents": "read"}
    assert all("permissions" not in job for job in document["jobs"].values())


def test_the_rehearsal_job_is_the_release_job_without_the_history_and_the_assets():
    released = _release()["jobs"]["rule-benchmark"]
    rehearsal = _rehearsal()["jobs"]["rule-benchmark"]
    for key in ("needs", "strategy", "runs-on", "defaults", "timeout-minutes", "env"):
        assert rehearsal[key] == released[key], key
    install = [step["run"] for step in released["steps"] if "pip install" in step.get("run", "")]
    assert [step["run"] for step in rehearsal["steps"] if "pip install" in step.get("run", "")] == install
    measuring = [step for step in rehearsal["steps"] if "rule_benchmark.py run" in step.get("run", "")]
    assert len(measuring) == 2
    plain, verified = sorted(measuring, key=lambda step: "--verify" in step["run"])
    assert plain["if"] == "${{ !inputs.verify }}" and verified["if"] == "${{ inputs.verify }}"
    assert verified["run"].replace(" --verify benchmarks/results.json", "") == plain["run"]
    release_measure = next(step for step in released["steps"] if "rule_benchmark.py run" in step.get("run", ""))
    assert verified["run"] == release_measure["run"]
    assert all(step["env"] == {"GITHUB_TOKEN": "${{ github.token }}"} for step in measuring)
    text = (WORKFLOWS / "rule-benchmark.yml").read_text(encoding="utf-8")
    assert "check-history" not in text and "gh release" not in text and "secrets." not in text
    uploads = [step for job in _rehearsal()["jobs"].values() for step in job["steps"]
               if str(step.get("uses", "")).startswith("actions/upload-artifact@")]
    assert [step["with"]["name"] for step in uploads] == ["dist"]


def test_the_rehearsal_pins_every_action_to_a_commit_release_yml_uses_and_names_no_macos_runner():
    text = (WORKFLOWS / "rule-benchmark.yml").read_text(encoding="utf-8")
    release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    released = {line.split("uses:", 1)[1].strip() for line in _uses_lines(release)}
    uses = _uses_lines(text)
    assert uses
    for line in uses:
        assert re.search(PINNED, line), line
        assert line.split("uses:", 1)[1].strip() in released, line
    assert "macos" not in text
    build = _rehearsal()["jobs"]["build"]
    assert build["runs-on"] == "ubuntu-latest" and "uv build" in _run(build["steps"])


# --- the rule pages (1.21.0, P6-15 fix guidance spec 6.12 E-9) ---------------------------------------------------------------

def test_the_rule_pages_job_checks_every_page_on_linux_after_build():
    job = _release()["jobs"]["rule-pages"]
    assert job["needs"] == "build" and job["runs-on"] == "ubuntu-latest"
    assert [step.get("run") for step in job["steps"] if "run" in step] == ["uv run --locked python scripts/check-rule-pages.py"]
    assert all("@" in step["uses"] and len(step["uses"].split("@")[1]) == 40 for step in job["steps"] if "uses" in step)


def test_nothing_is_published_before_the_rule_pages_answer():
    jobs = _release()["jobs"]
    for name in ("publish", "image"):
        assert jobs[name]["needs"][-1] == "rule-pages", name
