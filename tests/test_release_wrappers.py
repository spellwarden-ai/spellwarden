"""Spec 7.5: `scripts/release-wrappers.py` prepares the wrapper release branches after checking the manifest
against PyPI and the registry, and with `--tag` creates signed tags only on merged commits whose pipelines passed.
It never pushes. git, gh and docker are faked; nothing here opens a socket or runs a subprocess."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
spec = importlib.util.spec_from_file_location("release_wrappers", SCRIPTS / "release-wrappers.py")
rw = importlib.util.module_from_spec(spec)
sys.modules["release_wrappers"] = rw  # dataclasses look their module up while the class is created
spec.loader.exec_module(rw)

V = "1.0.0"
WHEEL = "a" * 64
SDIST = "b" * 64
DIGEST = "sha256:" + "c" * 64
ACTION_SHA = "d" * 40
GITLAB_SHA = "e" * 40
DEPS = "# from uv export\npyyaml==6.0.2 \\\n    --hash=sha256:" + "1" * 64 + "\n"
TEMPLATE = ('spec:\n  inputs:\n    stage:          {default: test}\n'
            '    image:          {default: "registry.gitlab.com/spellwarden-ai/scan/scanner-test:0.3.0"}\n---\n')


class Fake:
    """Answers commands by their longest matching prefix and records every call."""

    def __init__(self, answers: dict[tuple[str, ...], tuple[int, str]]):
        self.answers = answers
        self.calls: list[list[str]] = []

    def __call__(self, cmd, cwd=None):  # noqa: ARG002 (the runner's signature)
        self.calls.append(list(cmd))
        best = None
        for prefix, answer in self.answers.items():
            if tuple(cmd[:len(prefix)]) == prefix and (best is None or len(prefix) > len(best[0])):
                best = (prefix, answer)
        return best[1] if best else (0, "")


def _manifest():
    return json.dumps({"version": V, "wheel_sha256": WHEEL, "sdist_sha256": SDIST, "image_digest": DIGEST,
                       "action_commit": None, "component_commit": None})


def _pypi(wheel=WHEEL):
    return {"urls": [
        {"filename": f"spellwarden-{V}-py3-none-any.whl", "packagetype": "bdist_wheel", "digests": {"sha256": wheel}},
        {"filename": f"spellwarden-{V}.tar.gz", "packagetype": "sdist", "digests": {"sha256": SDIST}}]}


def _dirs(tmp_path):
    engine, action, gitlab = (tmp_path / n for n in ("spellwarden-oss", "scan-action", "scan-gitlab"))
    (engine / "docker").mkdir(parents=True)
    (engine / "docker" / "requirements.deps.txt").write_text(DEPS)
    (engine / "allowed_signers").write_text("# header\nowner@example.invalid namespaces=\"git\" ssh-ed25519 AAAA\n")
    (action / "fixtures" / "clean").mkdir(parents=True)
    (action / "fixtures" / "clean" / "expect.json").write_text('{"exit_code": 0}\n')
    (action / "requirements.txt").write_text("old\n")
    (gitlab / "templates").mkdir(parents=True)
    (gitlab / "templates" / "scan.yml").write_text(TEMPLATE)
    return engine, action, gitlab


def _ctx(tmp_path, runner, http):
    engine, action, gitlab = _dirs(tmp_path)
    return rw.Context(version=V, engine=engine, action=action, gitlab=gitlab, runner=runner, http=http)


PREPARE_OK = {
    ("gh", "release", "download"): (0, _manifest()),
    ("docker", "buildx", "imagetools", "inspect"): (0, json.dumps({"digest": DIGEST})),
    ("git", "status", "--porcelain"): (0, ""),
    ("git", "rev-parse", "--verify", "--quiet", f"refs/heads/release/{V}"): (1, ""),
}


def test_action_requirements_pins_the_wheel_and_pyyaml():
    text = rw.action_requirements(V, WHEEL, rw.deps_lines(DEPS))
    assert text.splitlines()[0].startswith("# Written by")
    assert f"spellwarden=={V} \\\n    --hash=sha256:{WHEEL}\n" in text
    assert "pyyaml==6.0.2" in text and "# from uv export" not in text


def test_set_component_image_replaces_the_one_default():
    new = rw.set_component_image(TEMPLATE, f"ghcr.io/spellwarden-ai/spellwarden:{V}@{DIGEST}")
    assert f'image:          {{default: "ghcr.io/spellwarden-ai/spellwarden:{V}@{DIGEST}"}}' in new
    assert new.count("ghcr.io") == 1 and "scanner-test" not in new
    with pytest.raises(rw.ReleaseError):
        rw.set_component_image("spec:\n  inputs: {}\n", "x")
    with pytest.raises(rw.ReleaseError):
        rw.set_component_image(TEMPLATE + TEMPLATE, "x")


def test_prepare_writes_both_files_on_release_branches_and_pushes_nothing(tmp_path):
    runner = Fake(PREPARE_OK)
    ctx = _ctx(tmp_path, runner, lambda _url: _pypi())
    printed = rw.prepare(ctx)
    assert f"sha256:{WHEEL}" in (ctx.action / "requirements.txt").read_text()
    assert f"spellwarden:{V}@{DIGEST}" in (ctx.gitlab / "templates" / "scan.yml").read_text()
    switches = [c for c in runner.calls if c[:3] == ["git", "switch", "-c"]]
    assert switches == [["git", "switch", "-c", f"release/{V}", "origin/main"]] * 2
    assert not any("push" in c for c in runner.calls)
    assert any(f"push -u origin release/{V}" in line for line in printed)


def test_prepare_retires_the_test_image_and_recopies_the_fixtures(tmp_path):
    runner = Fake(PREPARE_OK)
    ctx = _ctx(tmp_path, runner, lambda _url: _pypi())
    (ctx.gitlab / "ci" / "test-image").mkdir(parents=True)
    (ctx.gitlab / "ci" / "test-image" / "Dockerfile").write_text("FROM x\n")
    (ctx.gitlab / "ci" / "fixture-pipeline.yml").write_text(
        "include:\n  - component: x\n    inputs:\n      telemetry: false\n"
        "      image: $CI_REGISTRY_IMAGE/scanner-test:$CI_COMMIT_SHA  # the pre-1.0 test image of this commit; 1.0.0 removes this line\n")
    printed = rw.prepare(ctx)
    assert ["git", "rm", "-r", "-q", "ci/test-image"] in runner.calls
    assert (ctx.gitlab / "ci" / "fixture-pipeline.yml").read_text() == "include:\n  - component: x\n    inputs:\n      telemetry: false\n"
    assert ["git", "add", "-A", "--", "templates/scan.yml", "ci/fixture-pipeline.yml", "fixtures"] in runner.calls
    for copy in (ctx.gitlab / "fixtures", ctx.engine / "fixtures" / "repos"):
        assert (copy / "clean" / "expect.json").read_text() == '{"exit_code": 0}\n'
    assert any("fixtures/repos" in line and "commit" in line for line in printed)


def test_equal_fixtures_are_left_alone(tmp_path):
    ctx = _ctx(tmp_path, Fake(PREPARE_OK), lambda _url: _pypi())
    for copy in (ctx.gitlab / "fixtures", ctx.engine / "fixtures" / "repos"):
        (copy / "clean").mkdir(parents=True)
        (copy / "clean" / "expect.json").write_text('{"exit_code": 0}\n')
    runner = ctx.runner
    printed = rw.prepare(ctx)
    assert ["git", "add", "-A", "--", "templates/scan.yml"] in runner.calls
    assert not any(c[:2] == ["git", "rm"] for c in runner.calls)
    assert not any("fixtures/repos" in line for line in printed)


def test_a_byte_code_cache_is_no_fixture_difference(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    for root in (source, target):
        (root / "clean").mkdir(parents=True)
        (root / "clean" / "expect.json").write_text('{"exit_code": 0}\n')
    (source / "__pycache__").mkdir()
    (source / "__pycache__" / "make_repo.cpython-312.pyc").write_bytes(b"\x00")
    assert rw.sync_fixtures(source, target) is False
    (source / "clean" / "expect.json").write_text('{"exit_code": 1}\n')
    assert rw.sync_fixtures(source, target) is True
    assert not (target / "__pycache__").exists()


def test_prepare_refuses_a_pypi_hash_that_differs_from_the_manifest(tmp_path):
    ctx = _ctx(tmp_path, Fake(PREPARE_OK), lambda _url: _pypi(wheel="f" * 64))
    with pytest.raises(rw.ReleaseError, match="PyPI"):
        rw.prepare(ctx)


def test_prepare_refuses_an_image_digest_that_differs(tmp_path):
    answers = {**PREPARE_OK, ("docker", "buildx", "imagetools", "inspect"): (0, json.dumps({"digest": "sha256:" + "9" * 64}))}
    with pytest.raises(rw.ReleaseError, match="image"):
        rw.prepare(_ctx(tmp_path, Fake(answers), lambda _url: _pypi()))


def test_prepare_refuses_a_dirty_wrapper_checkout(tmp_path):
    answers = {**PREPARE_OK, ("git", "status", "--porcelain"): (0, " M action.yml\n")}
    with pytest.raises(rw.ReleaseError, match="uncommitted"):
        rw.prepare(_ctx(tmp_path, Fake(answers), lambda _url: _pypi()))


def _tag_answers(overrides: dict | None = None):
    answers = {
        ("gh", "release", "download"): (0, _manifest()),
        ("git", "config", "--get", "gpg.format"): (0, "ssh\n"),
        ("git", "config", "--get", "user.signingkey"): (0, "~/.ssh/tag_ed25519.pub\n"),
        ("git", "fetch"): (0, ""),
        ("git", "rev-parse", "origin/main"): (0, ACTION_SHA + "\n"),
        ("git", "show", "origin/main:requirements.txt"): (0, f"spellwarden=={V} \\\n    --hash=sha256:{WHEEL}\n"),
        ("git", "show", "origin/main:templates/scan.yml"): (0, f'image: {{default: "ghcr.io/spellwarden-ai/spellwarden:{V}@{DIGEST}"}}'),
        ("git", "rev-parse", "--verify", "--quiet"): (1, ""),
        ("gh", "api"): (0, "build\tcompleted\tsuccess\nlint\tcompleted\tsuccess\n"
                              "pull-request-cases\tcompleted\tskipped\nbase-settings (pull request)\tcompleted\tskipped\n"),
    }
    answers.update(overrides or {})
    return answers


def _gitlab_http(status="success"):
    return lambda _url: [{"id": 7, "sha": GITLAB_SHA, "status": status}]


def test_tag_creates_signed_tags_on_passed_commits_and_pushes_nothing(tmp_path):
    runner = Fake(_tag_answers())
    printed = rw.tag(_ctx(tmp_path, runner, _gitlab_http()))
    tags = [c for c in runner.calls if c[:2] == ["git", "tag"] and "-s" in c]
    assert [c[2:] for c in tags] == [
        ["-s", f"v{V}", "-m", f"spellwarden {V}", ACTION_SHA],
        ["-f", "-s", "v1", "-m", f"spellwarden v1, currently {V}", ACTION_SHA],
        ["-s", V, "-m", f"spellwarden {V}", ACTION_SHA],
    ]
    assert any(c[:5] == ["git", "-c", f"gpg.ssh.allowedSignersFile={tmp_path / 'spellwarden-oss' / 'allowed_signers'}",
                         "-c", "gpg.minTrustLevel=fully"]
               for c in runner.calls)
    assert not any("push" in c for c in runner.calls)
    assert f"git -C {tmp_path / 'scan-action'} push --force origin v1" in printed


def test_tag_refuses_a_failed_check_run(tmp_path):
    runner = Fake(_tag_answers({("gh", "api"): (0, "build\tcompleted\tfailure\n")}))
    with pytest.raises(rw.ReleaseError, match="check run"):
        rw.tag(_ctx(tmp_path, runner, _gitlab_http()))
    assert not any(c[:2] == ["git", "tag"] for c in runner.calls)


@pytest.mark.parametrize("runs", [
    "", "build\tcompleted\tcancelled\n", "build\tcompleted\ttimed_out\n", "build\tcompleted\taction_required\n",
    "build\tin_progress\t\n", "only-pr\tcompleted\tskipped\n",
])
def test_tag_refuses_check_runs_that_did_not_all_pass(runs, tmp_path):
    # Skipped and neutral runs pass (a push skips the pull-request-only jobs), but not alone, and nothing else does.
    runner = Fake(_tag_answers({("gh", "api"): (0, runs)}))
    with pytest.raises(rw.ReleaseError, match="check run"):
        rw.tag(_ctx(tmp_path, runner, _gitlab_http()))
    assert not any(c[:2] == ["git", "tag"] for c in runner.calls)


def test_tag_refuses_a_gitlab_pipeline_that_did_not_pass(tmp_path):
    with pytest.raises(rw.ReleaseError, match="pipeline"):
        rw.tag(_ctx(tmp_path, Fake(_tag_answers()), _gitlab_http("failed")))


def test_tag_refuses_without_an_ssh_signing_key(tmp_path):
    runner = Fake(_tag_answers({("git", "config", "--get", "gpg.format"): (1, "")}))
    with pytest.raises(rw.ReleaseError, match="gpg.format"):
        rw.tag(_ctx(tmp_path, runner, _gitlab_http()))


def test_tag_refuses_a_main_that_does_not_pin_the_release(tmp_path):
    runner = Fake(_tag_answers({("git", "show", "origin/main:requirements.txt"): (0, "spellwarden==0.3.0\n")}))
    with pytest.raises(rw.ReleaseError, match="requirements.txt"):
        rw.tag(_ctx(tmp_path, runner, _gitlab_http()))


def test_tag_refuses_an_existing_release_tag(tmp_path):
    runner = Fake(_tag_answers({("git", "rev-parse", "--verify", "--quiet"): (0, ACTION_SHA)}))
    with pytest.raises(rw.ReleaseError, match="exists"):
        rw.tag(_ctx(tmp_path, runner, _gitlab_http()))
