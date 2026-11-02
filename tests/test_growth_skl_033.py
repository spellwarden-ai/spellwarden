"""SW-SKL-033: skill drives the user's own signed-in browser over a remote-debugging port.
The rule is not registered yet, so the tests call the module's `detect` directly."""
from __future__ import annotations

import time

import pytest
from conftest import GENERATED, SKILL_FIXTURES, _read_dir, clean_md, make_package

from spellwarden_scan.package import Package
from spellwarden_scan.rules.growth_skl_033 import MALICIOUS, NIST, OWASP, RULE_ID, SEVERITY, TITLE, detect

NEW_IDS = frozenset({f"SW-SKL-{n:03d}" for n in range(32, 38)})
INTENT = "\nUse your existing Chrome, the one you are already logged in to. Do not launch your own browser.\n"


def run(body: str = "", **extra: str):
    return list(detect(Package.build(make_package({"SKILL.md": clean_md() + body, **extra}))))


def lines_of(findings) -> list[int]:
    return [f.location.line for f in findings]


def line_number(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    raise AssertionError(needle)


def test_module_constants():
    assert RULE_ID == "SW-SKL-033"
    assert TITLE == "Skill drives the user's own signed-in browser over a remote-debugging port"
    assert SEVERITY == "high"
    assert OWASP == ("ASI03",)
    assert NIST == ("AC-6", "IA-5")
    assert MALICIOUS is False


# --- attach path ------------------------------------------------------------------------------

def test_remote_debugging_toggle_with_identity_wording_fires_at_the_toggle_line():
    body = INTENT + "\n1. Open chrome://inspect/#remote-debugging in that browser.\n2. Tick the box.\n"
    findings = run(body)
    assert lines_of(findings) == [line_number(clean_md() + body, "chrome://inspect")]
    first = findings[0]
    assert first.rule_id == RULE_ID
    assert first.severity == "high"
    assert first.title == TITLE
    assert first.location.path == "SKILL.md"
    assert first.malicious_indicator is False
    assert "chrome://inspect" in first.evidence
    assert len(first.evidence) <= 300
    assert len(first.fingerprint) == 64


def test_allow_remote_debugging_wording_fires():
    body = INTENT + "\nIn the settings, switch on Allow remote debugging.\n"
    assert len(run(body)) == 1


@pytest.mark.parametrize("root", [
    'join(homedir(), "Library", "Application Support", "Google", "Chrome")',
    'join(homedir(), ".config", "google-chrome")',
    'join(process.env.LOCALAPPDATA, "Google", "Chrome", "User Data")',
    'join(process.env.LOCALAPPDATA, "Microsoft", "Edge", "User Data")',
    'join(homedir(), "Library/Application Support/BraveSoftware/Brave-Browser")',
    r'"C:\\Users\\me\\AppData\\Local\\Google\\Chrome\\User Data"',
])
def test_devtools_active_port_read_under_a_default_profile_fires_with_intent_in_skill_md(root):
    script = f'const dir = {root};\nconst port = readFileSync(join(dir, "DevToolsActivePort"), "utf8");\n'
    findings = run(INTENT, **{"scripts/attach.mjs": script})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/attach.mjs", 2)]


def test_launch_with_the_default_profile_directory_fires_at_the_launch_line():
    script = 'chrome --remote-debugging-port=9222 --profile-directory=Default\n'
    findings = run(INTENT, **{"scripts/open.sh": script})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/open.sh", 1)]


def test_launch_with_a_port_and_no_user_data_dir_fires():
    script = '#!/bin/sh\nexec google-chrome --remote-debugging-port=9222 "$@"\n'
    findings = run(INTENT, **{"scripts/open.sh": script})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/open.sh", 2)]


def test_attach_in_a_fenced_block_of_a_reference_file_uses_intent_from_skill_md():
    reference = "# Setup\n\n```sh\nchrome --remote-debugging-port=9222\n```\n"
    findings = run(INTENT, **{"references/setup.md": reference})
    assert [(f.location.path, f.location.line) for f in findings] == [("references/setup.md", 4)]


@pytest.mark.parametrize("intent", [
    "Works with your running Chrome.", "Reuses the browser you are signed in to: an existing session.",
    "It drives your real Chrome.", "Uses your everyday Chrome.", "Do not launch your own browser.",
    "The page stays logged-in.", "Your Chrome\u2019s existing session is used.",
])
def test_identity_wordings(intent):
    assert len(run(f"\n{intent}\nOpen chrome://inspect/#remote-debugging.\n")) == 1


def test_attach_without_identity_wording_does_not_fire():
    body = "\nTo debug a page, open chrome://inspect/#remote-debugging and pick a tab.\n"
    assert run(body) == []
    assert run("", **{"scripts/open.sh": "chrome --remote-debugging-port=9222\n"}) == []


# --- clone path -------------------------------------------------------------------------------

def test_copy_of_a_default_profile_plus_a_debugging_launch_fires_at_the_copy_line():
    script = (
        "from pathlib import Path\nimport shutil\n\n"
        'SRC = Path.home() / ".config" / "google-chrome"\n'
        "shutil.copytree(SRC, work, dirs_exist_ok=True)\n"
        'ctx = p.chromium.launch_persistent_context(str(work), args=["--remote-debugging-port=9333"])\n'
    )
    findings = run("", **{"scripts/clone.py": script})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/clone.py", 5)]


@pytest.mark.parametrize("copy", [
    'fs.cpSync(src, dest, { recursive: true });',
    'await fs.cp(src, dest, { recursive: true });',
    "robocopy $src $dest /E",
    "cp -r $SRC $DEST",
    "cp -a $SRC $DEST",
    "rsync -a $SRC/ $DEST/",
])
def test_copy_forms(copy):
    script = (
        'const src = join(homedir(), "Library", "Application Support", "Google", "Chrome");\n'
        f"{copy}\n"
        "launch --remote-debugging-port=9333\n"
    )
    findings = run("", **{"scripts/clone.mjs": script})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/clone.mjs", 2)]


def test_copy_in_markdown_instructions_fires():
    body = (
        "\nMake the agent browser see your sessions:\n\n```sh\n"
        'cp -r "$HOME/.config/google-chrome" ./agent-profile\n'
        "chrome --user-data-dir=./agent-profile --remote-debugging-port=9222\n```\n"
    )
    assert lines_of(run(body)) == [line_number(clean_md() + body, "cp -r")]


def test_default_root_as_user_data_dir_of_a_persistent_context_fires():
    script = (
        'const root = path.join(os.homedir(), ".config", "google-chrome");\n'
        "const context = await chromium.launchPersistentContext(root, { headless: false });\n"
    )
    findings = run("", **{"scripts/session.js": script})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/session.js", 2)]


def test_user_data_dir_flag_naming_a_default_root_with_a_debugging_port_fires():
    script = 'chromium --user-data-dir="$HOME/.config/google-chrome" --remote-debugging-port=9222\n'
    assert len(run("", **{"scripts/open.sh": script})) == 1


def test_copy_of_a_default_profile_without_any_debugging_launch_does_not_fire():
    script = 'SRC = Path.home() / ".config" / "google-chrome"\nshutil.copytree(SRC, backup)\n'
    assert run("", **{"scripts/backup.py": script}) == []


# --- negatives --------------------------------------------------------------------------------

def test_dedicated_profile_folder_does_not_fire():
    script = (
        'const profile = join(homedir(), ".config", "tab-helper", "browser-profile");\n'
        'launch(["--remote-debugging-port=9222", `--user-data-dir=${profile}`]);\n'
    )
    assert run(INTENT, **{"scripts/open.mjs": script}) == []
    assert run(INTENT, **{"scripts/open.sh": "chrome --remote-debugging-port=9222 --user-data-dir=$HOME/.tab-helper/profile\n"}) == []


def test_a_folder_that_only_starts_like_a_default_root_does_not_fire():
    script = (
        'dir = Path.home() / ".config" / "google-chrome-agent"\n'
        "shutil.copytree(template, dir)\n"
        'chrome(f"--user-data-dir={dir}", "--remote-debugging-port=9222")\n'
    )
    assert run(INTENT, **{"scripts/setup.py": script}) == []


def test_temp_profile_does_not_fire():
    script = (
        "import tempfile\nimport shutil\n"
        'work = tempfile.mkdtemp(prefix="browser-")\n'
        "shutil.copytree(TEMPLATE, work, dirs_exist_ok=True)\n"
        'subprocess.run(["chrome", "--remote-debugging-port=9222", f"--user-data-dir={work}"])\n'
    )
    assert run(INTENT, **{"scripts/run.py": script}) == []


def test_optional_attach_flag_with_a_self_managed_default_browser_does_not_fire():
    body = (
        "\nThe tool launches its own browser in a fresh profile.\n\n"
        "Optionally, to reuse an existing session, open chrome://inspect/#remote-debugging and pass --attach.\n"
    )
    assert run(body) == []
    assert run(INTENT + body) == []


def test_detection_regex_listing_profile_paths_does_not_fire():
    script = (
        "import re\nimport shutil\n"
        'PROFILE_PATHS = re.compile(r"(Application Support/Google/Chrome|\\.config/google-chrome|Google/Chrome/User Data|BraveSoftware)")\n'
        "shutil.copytree(report_template, out)\n"
        'subprocess.run(["chrome", "--remote-debugging-port=9222"])\n'
    )
    assert run("", **{"scripts/check.py": script}) == []


def test_detection_string_list_does_not_fire():
    script = (
        "// Flag these directories when a tool tries to read them (deny list).\n"
        "const DENIED = [\n"
        '  "Application Support/Google/Chrome",\n'
        '  ".config/google-chrome",\n'
        "];\n"
        "fs.cpSync(a, b, { recursive: true });\n"
        "launch --remote-debugging-port=9222\n"
    )
    assert run("", **{"scripts/guard.mjs": script}) == []


def test_headless_test_browser_against_localhost_does_not_fire():
    script = "chrome --headless --remote-debugging-port=9222 http://localhost:3000/\n"
    assert run(INTENT, **{"scripts/test.sh": script}) == []


def test_prose_that_only_describes_the_abuse_does_not_fire():
    body = (
        "\n## Threats\n\nAttackers abuse chrome://inspect/#remote-debugging to drive a victim's existing session.\n"
        "Never turn on Allow remote debugging for a browser you are logged in to.\n"
    )
    assert run(body) == []


def test_files_that_are_not_scripts_or_markdown_are_not_read():
    assert run(INTENT, **{"notes.txt": "chrome --remote-debugging-port=9222\n", "data.json": '{"a": "chrome://inspect/#remote-debugging"}'}) == []


# --- fixtures -----------------------------------------------------------------------------------

def _fixture(side: str) -> Package:
    return Package.build(_read_dir(SKILL_FIXTURES / RULE_ID / side))


def test_positive_fixture_fires_and_negative_fixture_does_not():
    positive = list(detect(_fixture("positive")))
    assert {f.location.path for f in positive} == {"SKILL.md", "scripts/attach.mjs", "scripts/clone.py"}
    assert list(detect(_fixture("negative"))) == []


# --- linear time ----------------------------------------------------------------------------

@pytest.mark.parametrize("unit", [
    "--remote-debugging-port=", "--remote-debugging-port=9222 --profile-directory=Default ",
    ".config/google-chrome ", "google-chrome-", "your existing ", "cp -r ", "chrome://inspect/#remote-debugging ",
    '", "', "Google/Chrome/User Data/",
])
def test_long_line_is_read_in_linear_time(unit):
    line = (unit * (300_000 // len(unit) + 1))[:300_000]
    files = {"SKILL.md": clean_md() + INTENT, "scripts/x.sh": line + "\n", "references/r.md": line + "\n"}
    package = Package.build(make_package(files))
    started = time.perf_counter()
    list(detect(package))
    assert time.perf_counter() - started < 1.0


def test_output_is_bounded():
    script = "chrome --remote-debugging-port=9222\n" * 5_000
    assert len(run(INTENT, **{"scripts/x.sh": script})) <= 10


# --- invariant 4: no finding on any existing skill fixture ------------------------------------

def _existing_skill_packages():
    for directory in sorted(SKILL_FIXTURES.iterdir()):
        if not directory.is_dir() or directory.name in NEW_IDS:
            continue
        for side in sorted(p for p in directory.iterdir() if p.is_dir()):
            generator = GENERATED.get(f"{directory.name}/{side.name}")
            yield f"{directory.name}/{side.name}", (generator() if generator is not None else _read_dir(side))


def test_no_finding_on_any_existing_skill_fixture():
    seen = 0
    for name, files in _existing_skill_packages():
        seen += 1
        assert list(detect(Package.build(files))) == [], name
    assert seen >= 30
