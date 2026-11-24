"""1.22.0 (P6-4 spec 6.1, claims G1 to G7 and G9): the disguise generator `benchmarks/disguise.py` on a hand-written harmless skill,
never on a benchmark sample. `benchmarks/` is not in the wheel or the sdist, so this file skips where it is absent."""
from __future__ import annotations

import ast
import base64
import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "benchmarks" / "disguise.py"
if not SCRIPT.exists():
    pytest.skip("benchmarks/ is not in an sdist", allow_module_level=True)

_spec = importlib.util.spec_from_file_location("disguise_under_test", SCRIPT)
disguise = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(disguise)

from spellwarden_scan.normalise import fold  # noqa: E402

FRONT = "---\nname: demo-skill\ndescription: A demo skill for the tests.\nlicense: MIT\nversion: 1.0.0\n---\n"
SKILL = (FRONT + "\n# Demo skill\r\n\nRead the notes first, then follow every step below.\n"
         "Always check the output before you answer.\n\n```bash\necho 'hello world' && ls -la /tmp\n```\n\n"
         "```json\n{\"name\": \"value\"}\n```\nLast words here.\n").encode()
SCRIPT_PY = b"#!/usr/bin/env python3\nprint('hello there')\nname = \"some text here\"\n"
FILES = {"SKILL.md": SKILL, "scripts/run.py": SCRIPT_PY, "scripts/run.sh": b"echo \"quoted words\" && mkdir build\n",
         "logo.png": b"\x89PNG\r\n\x1a\n\x00\xff\xfe", "latin.md": "caf\u00e9 notes\n".encode("latin-1"), "data.json": b'{"key": "value"}\n'}
PROSE_TECHNIQUES = ("lookalike", "zero-width", "markup", "translation")


def lines(data: bytes) -> list[str]:
    return data.decode("utf-8").splitlines(keepends=True)


def test_the_same_input_gives_the_same_bytes_and_another_key_other_choices():
    """G1."""
    for technique in disguise.TECHNIQUE_IDS:
        assert disguise.variant(FILES, technique, key="item/1") == disguise.variant(FILES, technique, key="item/1"), technique
    differ = [technique for technique in ("lookalike", "zero-width", "padding", "markup")
              if disguise.variant(FILES, technique, key="item/1") != disguise.variant(FILES, technique, key="other/1")]
    assert differ == ["lookalike", "zero-width", "padding", "markup"]


def test_the_constants_of_generator_version_1():
    assert (disguise.GENERATOR_VERSION, disguise.SEED) == (1, "spellwarden-disguise-1")
    assert disguise.TECHNIQUE_IDS == ("lookalike", "zero-width", "encoding-1", "encoding-2", "joined", "padding", "markup", "translation")
    assert dict(disguise.TECHNIQUES)["zero-width"] == "zero-width characters inside words"
    assert 120 <= len(disguise.WORDS) <= 160
    with pytest.raises(ValueError):
        disguise.variant(FILES, "rot13", key="item/1")


def test_the_generator_imports_only_the_standard_library_and_the_package_module_and_writes_nothing():
    """G2."""
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert {name.split(".")[0] for name in imported if not name.startswith("spellwarden_scan")} <= set(sys.stdlib_module_names) | {
        "__future__"}
    assert {name for name in imported if name.startswith("spellwarden_scan")} == {"spellwarden_scan.package"}
    assert not {name.split(".")[0] for name in imported} & {"os", "pathlib", "subprocess", "socket", "urllib", "logging", "io"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            assert name not in ("open", "print", "write", "write_text", "write_bytes"), name


@pytest.mark.parametrize("technique", ("lookalike", "zero-width", "encoding-1", "encoding-2", "joined", "padding", "markup", "translation"))
def test_every_technique_keeps_what_6_1_3_keeps(technique):
    """G3: paths, binary and non-UTF-8 files, other text files, the front matter, the fence lines and the line endings."""
    out = disguise.variant(FILES, technique, key="item/1")
    assert set(out) == set(FILES)
    for path in ("logo.png", "latin.md", "data.json"):
        assert out[path] == FILES[path], path
    text = out["SKILL.md"].decode("utf-8")
    assert text.startswith(FRONT)
    assert "\r\n" in text and text.count("\r\n") == SKILL.decode().count("\r\n")
    assert [line for line in lines(out["SKILL.md"]) if line.startswith("```")] == ["```bash\n", "```\n", "```json\n", "```\n"]
    assert '{"name": "value"}\n' in text  # a block of another language is left as it is


@pytest.mark.parametrize("technique", PROSE_TECHNIQUES)
def test_a_prose_technique_leaves_scripts_and_code_blocks_byte_for_byte(technique):
    """G3."""
    out = disguise.variant(FILES, technique, key="item/1")
    assert out["scripts/run.py"] == SCRIPT_PY and out["scripts/run.sh"] == FILES["scripts/run.sh"]
    assert "echo 'hello world' && ls -la /tmp\n" in out["SKILL.md"].decode("utf-8")
    assert out["SKILL.md"] != SKILL


def test_joined_leaves_prose_byte_for_byte():
    """G3."""
    out = disguise.variant(FILES, "joined", key="item/1")
    prose = [line for line in lines(SKILL) if not line.startswith(("echo", "```", "{"))]
    assert all(line in lines(out["SKILL.md"]) for line in prose)
    assert out["scripts/run.py"] != SCRIPT_PY


def test_folding_a_lookalike_variant_gives_the_prose_back():
    """G4."""
    out = disguise.variant(FILES, "lookalike", key="item/1")["SKILL.md"].decode("utf-8")
    assert out != SKILL.decode("utf-8")
    assert [fold(line, ("lookalike",)) for line in out.split("\n")] == SKILL.decode("utf-8").split("\n")


def test_removing_the_zero_width_characters_gives_the_original():
    """G5."""
    out = disguise.variant(FILES, "zero-width", key="item/1")["SKILL.md"].decode("utf-8")
    assert re.sub("[\u200b\u200c\u200d\u2060]", "", out) == SKILL.decode("utf-8") and out != SKILL.decode("utf-8")
    assert not re.search(r"\b(Read|notes|follow|every|check)\b", out)  # every word of four letters or more is split


@pytest.mark.parametrize("layers", (1, 2))
def test_encoding_replaces_prose_lines_by_base64_and_code_by_its_carrier(layers):
    """G6."""
    technique = f"encoding-{layers}"
    out = disguise.variant(FILES, technique, key="item/1")
    text = re.split(r"\r\n|\r|\n", out["SKILL.md"].decode("utf-8"))
    sentence = text.index(disguise.ENCODED_SENTENCE[layers])
    assert sentence == FRONT.count("\n")  # right after the front matter, before the first prose line
    original = re.split(r"\r\n|\r|\n", SKILL.decode("utf-8"))
    encoded = [line for line in text[sentence + 1:] if line and not line.startswith(("```", "echo", "{"))]
    decoded = []
    for line in encoded:
        data = line.encode()
        for _ in range(layers):
            data = base64.b64decode(data, validate=True)
        decoded.append(data.decode("utf-8"))
    assert decoded == [line for line in original[FRONT.count("\n"):] if line.strip() and not line.startswith(("```", "echo", "{"))]
    block = disguise.carrier("shell", "echo 'hello world' && ls -la /tmp", layers)
    assert block in text
    # the script's text after its `#!` line, without the line ending of its last line, which stays after the carrier
    assert out["scripts/run.py"].decode() == ("#!/usr/bin/env python3\n"
                                              + disguise.carrier("python", "print('hello there')\nname = \"some text here\"", layers) + "\n")


def test_each_carrier_is_the_one_of_6_1_5():
    """G6."""
    assert disguise.carrier("shell", "ls", 1) == "echo 'bHM=' | base64 -d | sh"
    assert disguise.carrier("shell", "ls", 2) == "echo 'YkhNPQ==' | base64 -d | base64 -d | sh"
    assert disguise.carrier("python", "ls", 1) == 'exec(__import__("base64").b64decode("bHM="))'
    assert disguise.carrier("python", "ls", 2) == 'exec(__import__("base64").b64decode(__import__("base64").b64decode("YkhNPQ==")))'
    assert disguise.carrier("js", "ls", 1) == 'eval(atob("bHM="))'
    assert disguise.carrier("js", "ls", 2) == 'eval(atob(atob("YkhNPQ==")))'
    assert disguise.carrier("powershell", "ls", 1) == 'iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("bHM=")))'
    assert disguise.carrier("ruby", "ls", 1) == 'eval(Base64.decode64("bHM="))'
    assert disguise.carrier("perl", "ls", 1) == 'use MIME::Base64; eval(decode_base64("bHM="));'


def test_joined_splits_shell_words_outside_quotes_and_string_literals_elsewhere():
    """G7: `echo`, `mkdir` and `build` each get an empty pair, the quoted words none; each literal of four or more characters is
    split in two joined by `+` (`.` in Perl)."""
    out = disguise.variant(FILES, "joined", key="item/1")
    shell = out["scripts/run.sh"].decode()
    assert shell.count("''") == 3 and '"quoted words"' in shell and shell.replace("''", "") == FILES["scripts/run.sh"].decode()
    python = out["scripts/run.py"].decode()
    assert "' + '" in python and '" + "' in python
    assert python.replace("' + '", "").replace('" + "', "") == SCRIPT_PY.decode()
    perl = disguise.variant({"a.pl": b'print "hello there";\n'}, "joined", key="k/1")["a.pl"].decode()
    assert perl.count('" . "') == 1 and perl.replace('" . "', "") == 'print "hello there";\n'


def test_padding_widens_each_lone_space_with_its_scope_s_characters():
    """G7."""
    out = disguise.variant(FILES, "padding", key="item/1")
    shell = out["scripts/run.sh"].decode()
    assert re.sub(r"[ \t]{2,6}", " ", shell) == FILES["scripts/run.sh"].decode() and " " in shell
    assert not set(shell) & set(disguise.PROSE_PADDING[2:])
    prose = [line for line in out["SKILL.md"].decode().split("\n") if "notes" in line][0]
    assert re.sub("[ \t\u00a0\u2002\u2003\u3000]{2,6}", " ", prose) == "Read the notes first, then follow every step below."


def test_markup_uses_comments_references_or_emphasis_inside_long_words():
    """G7."""
    out = disguise.variant(FILES, "markup", key="item/1")["SKILL.md"].decode()
    plain = re.sub(r"<!-- -->|\*\*", "", out)
    plain = re.sub(r"&#(\d+);", lambda match: chr(int(match.group(1))), plain)
    assert plain == SKILL.decode() and out != SKILL.decode()


def test_translation_replaces_listed_words_and_keeps_their_case():
    """G7."""
    out = disguise.variant({"SKILL.md": (FRONT + "Read the FILE, then run it.\n").encode()}, "translation", key="k/1")
    assert out["SKILL.md"].decode() == FRONT + "Lee el ARCHIVO, luego ejecuta lo.\n"
