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


def test_profile_directory_default_inside_a_dedicated_user_data_dir_does_not_fire():
    # Review r0:F8, decided: `--profile-directory` names a profile inside the user data directory. Without
    # `--user-data-dir` that is the user's own (fires, above); inside a dedicated folder it is that folder's own profile.
    script = "chrome --remote-debugging-port=9222 --user-data-dir=$HOME/.tab-helper/profile --profile-directory=Default\n"
    assert run(INTENT, **{"scripts/open.sh": script}) == []
    own = "chrome --remote-debugging-port=9222 --user-data-dir=\"$HOME/.config/google-chrome\" --profile-directory=Default\n"
    assert lines_of(run(INTENT, **{"scripts/open.sh": own})) == [1]


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


# --- revision: any browser scheme, chrome-devtools-mcp auto-connect, Chinese wording, one-hop copies -----------

@pytest.mark.parametrize("scheme", ["brave", "edge"])
def test_toggle_in_another_browser_scheme_fires_at_the_toggle_line(scheme):
    body = (
        "\nConnect to the user's running Chrome.\n\n"
        f"Tell the user to enable remote debugging at {scheme}://inspect/#remote-debugging first.\n"
    )
    assert lines_of(run(body)) == [line_number(clean_md() + body, f"{scheme}://inspect")]


def test_templated_scheme_toggle_in_a_script_string_fires():
    script = "const browser = pick();\nconsole.log(`Open ${browser}://inspect/#remote-debugging and tick the box`);\n"
    findings = run(INTENT, **{"scripts/hint.mjs": script})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/hint.mjs", 2)]


def test_slashless_toggle_in_a_script_comment_fires():
    script = "const port = 9222;\n// Ask the person to open chrome://inspect#remote-debugging first.\n"
    findings = run(INTENT, **{"scripts/hint.mjs": script})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/hint.mjs", 2)]


CHINESE = "\n本技能通过 CDP 直接连接用户的日常浏览器，复用已有的页面。\n"


def test_chinese_everyday_browser_attach_statement_fires_at_that_line():
    findings = run(CHINESE)
    assert [(f.location.path, f.location.line) for f in findings] == [("SKILL.md", line_number(clean_md() + CHINESE, "CDP"))]


def test_chinese_skill_md_gives_the_intent_for_a_sibling_script():
    script = "// Allow remote debugging in the browser, then run the next step.\nconst port = 9222;\n"
    findings = run(CHINESE, **{"scripts/hint.mjs": script})
    assert ("scripts/hint.mjs", 1) in [(f.location.path, f.location.line) for f in findings]


@pytest.mark.parametrize("flag", ["--auto-connect", "--autoConnect"])
def test_chrome_devtools_mcp_auto_connect_fires_at_the_flag_line(flag):
    reference = (
        "# MCP setup\n\nThe MCP must attach to existing Chrome.\n\n```sh\n"
        f"npx chrome-devtools-mcp@latest {flag}\n```\n"
    )
    findings = run("", **{"references/mcp.md": reference})
    assert [(f.location.path, f.location.line) for f in findings] == [("references/mcp.md", 6)]


def test_js_copy_of_a_root_returned_by_a_function_far_above_fires_at_the_copy_line():
    filler = "".join(f"// unrelated note {n}\n" for n in range(25))
    script = (
        "import { join } from 'node:path';\nimport { cpSync } from 'node:fs';\n\n"
        "function getDefault() {\n  return join(home, '.config', 'google-chrome');\n}\n\n"
        f"{filler}\n"
        "function clone(src, dst) {\n  cpSync(src, dst, { recursive: true });\n}\n\n"
        "const d = getDefault();\nclone(d, OWN_DIR);\n"
        "launch(['--remote-debugging-port=9222']);\n"
    )
    findings = run("", **{"scripts/clone.mjs": script})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/clone.mjs", line_number(script, "cpSync(src"))]


def test_js_copy_of_a_root_function_call_passed_straight_in_fires():
    filler = "".join(f"// unrelated note {n}\n" for n in range(25))
    script = (
        "function getDefault() {\n  return join(home, '.config', 'google-chrome');\n}\n\n"
        f"{filler}\n"
        "const clone = (src, dst) => {\n  cpSync(src, dst, { recursive: true });\n};\n\n"
        "clone(getDefault(), OWN_DIR);\nlaunch(['--remote-debugging-port=9222']);\n"
    )
    assert lines_of(run("", **{"scripts/clone.mjs": script})) == [line_number(script, "cpSync(src")]


def test_python_copy_of_a_root_returned_by_a_function_far_above_fires_at_the_copy_line():
    filler = "".join(f"    # unrelated note {n}\n" for n in range(16))
    script = (
        "import os\nimport shutil\n\n\n"
        'def default_profile():\n    return os.path.join(os.environ["LOCALAPPDATA"], "Google", "Chrome", "User Data")\n\n\n'
        f"def clone(src, dst):\n{filler}    shutil.copytree(src, dst)\n\n\n"
        "clone(default_profile(), own_dir)\n"
        "ctx = p.chromium.launch_persistent_context(own_dir)\n"
    )
    findings = run("", **{"scripts/clone.py": script})
    assert [(f.location.path, f.location.line) for f in findings] == [("scripts/clone.py", line_number(script, "copytree"))]


def test_copy_hop_through_a_function_that_is_fed_a_template_does_not_fire():
    filler = "".join(f"// unrelated note {n}\n" for n in range(25))
    script = (
        "function getDefault() {\n  return join(home, '.config', 'google-chrome');\n}\n\n"
        f"{filler}\n"
        "function clone(src, dst) {\n  cpSync(src, dst, { recursive: true });\n}\n\n"
        "clone(TEMPLATE_DIR, OWN_DIR);\nlaunch(['--remote-debugging-port=9222']);\n"
    )
    assert run("", **{"scripts/clone.mjs": script}) == []


def test_copy_hop_through_a_function_that_only_lists_roots_in_a_detection_pattern_does_not_fire():
    filler = "".join(f"    # unrelated note {n}\n" for n in range(16))
    script = (
        "import re\nimport shutil\n\n\n"
        'def known_profiles():\n    return re.compile(r"\\.config/google-chrome")\n\n\n'
        f"def clone(src, dst):\n{filler}    shutil.copytree(src, dst)\n\n\n"
        "clone(known_profiles(), own_dir)\n"
        "ctx = p.chromium.launch_persistent_context(own_dir)\n"
    )
    assert run("", **{"scripts/clone.py": script}) == []


@pytest.mark.parametrize("body", [
    "\nUse your existing Chrome.\n\n## Detection and security\n\nBefore anything else, check brave://inspect/#remote-debugging.\n",
    "\nUse your existing Chrome.\n\nAttackers ask a victim to open brave://inspect/#remote-debugging.\n",
])
def test_toggle_in_another_scheme_under_detection_or_attacker_wording_does_not_fire(body):
    assert run(body) == []


@pytest.mark.parametrize("scheme", ["brave", "edge"])
def test_toggle_in_another_scheme_without_identity_intent_does_not_fire(scheme):
    assert run(f"\nOpen {scheme}://inspect/#remote-debugging and pick a tab to debug.\n") == []


def test_chinese_login_state_kept_in_the_tools_own_user_data_dir_does_not_fire():
    body = "\n登录态保存在工具自己的 userDataDir 中，不会碰你的浏览器。\n"
    script = "chrome --remote-debugging-port=9222 --user-data-dir=$HOME/.tab-helper/profile\n"
    assert run(body, **{"scripts/open.sh": script}) == []


def test_chinese_negated_cdp_statement_about_the_everyday_browser_does_not_fire():
    assert run("\n不要通过 CDP 连接用户的日常浏览器。\n") == []


def test_english_line_saying_not_via_cdp_does_not_fire():
    assert run("\nThe skill uses the user's real Chrome profile files, not via CDP.\n") == []


def test_auto_connect_flag_of_other_tools_does_not_fire():
    config = "export default {\n  autoConnect: true,\n};\n"
    assert run(INTENT, **{"scripts/wallet.mjs": config}) == []
    assert run(INTENT, **{"scripts/wallet.sh": "wallet-cli --autoConnect\n"}) == []


def test_chrome_devtools_mcp_auto_connect_without_identity_intent_does_not_fire():
    assert run("", **{"references/mcp.md": "```sh\nnpx chrome-devtools-mcp@latest --auto-connect\n```\n"}) == []


def test_chrome_devtools_mcp_auto_connect_next_to_a_dedicated_user_data_dir_does_not_fire():
    line = "npx chrome-devtools-mcp@latest --auto-connect --user-data-dir=$HOME/.tab-helper/profile\n"
    assert run(INTENT, **{"scripts/mcp.sh": line}) == []


def test_powershell_robocopy_between_dedicated_profiles_does_not_fire():
    script = (
        '$backup = "$env:TEMP\\profile-backup"\n'
        'robocopy $backup "$env:USERPROFILE\\.tab-helper\\profile" /E\n'
        '& chrome --remote-debugging-port=9222 --user-data-dir="$env:USERPROFILE\\.tab-helper\\profile" --profile-directory=Default\n'
    )
    assert run(INTENT, **{"scripts/restore.ps1": script}) == []


def test_many_function_definitions_are_traced_in_linear_time():
    functions = "".join(f"function f{n}(a, b) {{\n  cpSync(a, b, {{ recursive: true }});\n  return f{n}(a, b);\n}}\n" for n in range(10_000))
    script = (
        f"{functions}function getDefault() {{\n  return join(home, '.config', 'google-chrome');\n}}\n"
        "launch(['--remote-debugging-port=9222']);\n"
    )
    package = Package.build(make_package({"SKILL.md": clean_md(), "scripts/many.mjs": script}))
    assert len(package.text_files) == 2  # the script is under the size cap, so it is really read
    started = time.perf_counter()
    list(detect(package))
    assert time.perf_counter() - started < 1.0


def test_many_copy_lines_in_one_function_with_many_long_call_sites_are_traced_in_linear_time():
    calls = "".join(f"copyprofile('{'a' * 380}{n}', dst)\n" for n in range(200))
    script = (
        "// --remote-debugging-port\nfunction copyprofile(src) {\n" + "  cp -r src dest\n" * 8_000 + "}\n" + calls
    )
    package = Package.build(make_package({"SKILL.md": clean_md(), "scripts/c.js": script}))
    assert len(package.text_files) == 2  # the script is under the size cap, so it is really read
    started = time.perf_counter()
    list(detect(package))
    assert time.perf_counter() - started < 1.0


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
    '", "', "Google/Chrome/User Data/", "://inspect/#remote-debugging ", "chrome-devtools-mcp --auto-connect ",
])
def test_long_line_is_read_in_linear_time(unit):
    line = (unit * (300_000 // len(unit) + 1))[:300_000]
    files = {"SKILL.md": clean_md() + INTENT, "scripts/x.sh": line + "\n", "references/r.md": line + "\n"}
    package = Package.build(make_package(files))
    started = time.perf_counter()
    list(detect(package))
    assert time.perf_counter() - started < 1.0


@pytest.mark.parametrize("unit", ["copy-item ", "cp ", "robocopy ", "rsync -"])
def test_long_copy_command_line_is_read_in_linear_time(unit):
    # the clone gate is open, so every line is examined for a copy command
    launch = "chrome --remote-debugging-port=9222 --user-data-dir=/tmp/x\n"
    line = (unit * (300_000 // len(unit) + 1))[:300_000]
    files = {"SKILL.md": clean_md() + INTENT, "scripts/x.sh": launch + line + "\n"}
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
