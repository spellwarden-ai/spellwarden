"""Spec 7.4: the pre-release workflow's e2e jobs hold the checks the spec names."""
from __future__ import annotations

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
