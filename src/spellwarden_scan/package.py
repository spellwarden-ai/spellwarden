"""What skill rules see (spec 5.3): decoded text files, binary files, the
fenced code blocks of every Markdown file, the metadata and the executable
paths. Built once per scan."""
from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass

from spellwarden_scan.frontmatter import metadata_of
from spellwarden_scan.model import Metadata

TEXT_MAX = 2**20
REPLACEMENT_SHARE = 0.05
SCRIPT_EXTENSIONS = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".ts", ".rb", ".ps1", ".pl")
SHELL_LANGUAGES = ("sh", "bash", "shell", "zsh", "console")
CODE_LANGUAGES = SHELL_LANGUAGES + ("python", "js", "javascript", "ts", "typescript", "powershell")
_SHELL_STARTS = ("$ ", "curl", "wget", "pip", "npm", "npx", "git", "rm", "sudo")
# CommonMark fences: an opener is three or more backticks or tildes and any info string (a backtick fence's info
# string holds no backtick); the language is the info string's first word, braces and dots stripped (`{bash}`,
# `.sh`, `bash title=run.sh`). A closing fence is the opening character, at least as long, with nothing after it.
_OPENER = re.compile(r"^(`{3,}(?=[^`]*$)|~{3,})(.*)$")
_CLOSER = re.compile(r"^(`{3,}|~{3,})$")
_LANGUAGE = re.compile(r"[A-Za-z0-9_+-]+")


def _indent(line: str) -> int:
    expanded = line.expandtabs(4)
    return len(expanded) - len(expanded.lstrip(" "))


def split_lines(text: str) -> tuple[str, ...]:
    """The file's lines as an editor and an agent number them: split on `\\n` only, a trailing `\\r`
    dropped. `str.splitlines()` also splits on `\\x0b`, `\\x0c`, `\\x1c`-`\\x1e`, `\\x85`, U+2028 and U+2029,
    which would shift every line number after one of them (spec 5.3: line numbers are the file's)."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return tuple(line[:-1] if line.endswith("\r") else line for line in lines)


@dataclass(frozen=True)
class TextFile:
    path: str
    text: str
    lines: tuple[str, ...]
    head: bytes = b""  # the raw first eight bytes: SW-SKL-010 reads magic numbers here, never from re-encoded text


@dataclass(frozen=True)
class BinaryFile:
    path: str
    head: bytes
    size: int


@dataclass(frozen=True)
class CodeBlock:
    path: str
    language: str
    text: str
    first_line: int

    @property
    def lines(self) -> tuple[str, ...]:
        return split_lines(self.text)


def _decode(content: bytes) -> str | None:
    """UTF-8 with replacement; `None` (binary) when too large or too damaged."""
    if len(content) > TEXT_MAX:
        return None
    text = content.decode("utf-8", errors="replace")
    if content and text.count("\ufffd") > len(content) * REPLACEMENT_SHARE:
        return None
    return text


def _code_blocks(path: str, lines: tuple[str, ...]) -> list[CodeBlock]:
    blocks: list[CodeBlock] = []
    fence: str | None = None
    width = 0
    language = ""
    start = 0
    body: list[str] = []

    def finish() -> None:
        nonlocal language
        if not language:
            first = next((b for b in body if b.strip()), "")
            if first.strip().startswith(_SHELL_STARTS):
                language = "sh"
        blocks.append(CodeBlock(path, language, "\n".join(body), start))

    indent = 0
    for number, line in enumerate(lines, start=1):
        if fence is None:
            # Any indentation opens a block (a fence inside a list item is still code an agent runs).
            opener = _OPENER.match(line.strip())
            if opener:
                fence, width, indent = opener.group(1)[0], len(opener.group(1)), _indent(line)
                word = _LANGUAGE.search(opener.group(2))
                language, start, body = (word.group(0).lower() if word else ""), number + 1, []
            continue
        # CommonMark: a closing fence repeats the opening character, is at least as long, has no info string
        # and is indented less than four spaces more than the opener (a deeper one is content).
        closer = _CLOSER.match(line.strip())
        if closer and closer.group(1)[0] == fence and len(closer.group(1)) >= width and _indent(line) < indent + 4:
            finish()
            fence = None
            continue
        body.append(line)
    if fence is not None:
        finish()  # an unclosed fence runs to the end of the file, as an agent reads it
    return blocks


class Package:
    """The package view. Build it with `Package.build(files, root=..., executable_paths=...)`."""

    def __init__(self, root: str, text_files: tuple[TextFile, ...], binary_files: tuple[BinaryFile, ...],
                 code_blocks: tuple[CodeBlock, ...], metadata: Metadata, executable_paths: frozenset[str]) -> None:
        self.root = root
        self.text_files = text_files
        self.binary_files = binary_files
        self.code_blocks = code_blocks
        self.metadata = metadata
        self.executable_paths = executable_paths

    @classmethod
    def build(cls, files: Mapping[str, bytes], *, root: str = "", executable_paths: Collection[str] = ()) -> Package:
        root = root.strip("/")
        prefix = f"{root}/" if root else ""
        texts: list[TextFile] = []
        binaries: list[BinaryFile] = []
        blocks: list[CodeBlock] = []
        for path in sorted(files):
            if prefix and not path.startswith(prefix):
                continue
            content = files[path]
            text = _decode(content)
            if text is None:
                binaries.append(BinaryFile(path, content[:8], len(content)))
                continue
            lines = split_lines(text)
            texts.append(TextFile(path, text, lines, content[:8]))
            if path.lower().endswith(".md"):
                blocks.extend(_code_blocks(path, lines))
        # Only the executable entries under `root` belong to this package: a sibling directory's binaries are not its finding.
        kept = frozenset(path for path in executable_paths if not prefix or path.startswith(prefix))
        return cls(root, tuple(texts), tuple(binaries), tuple(blocks), metadata_of(files, root), kept)

    def instructions(self) -> tuple[TextFile, ...]:
        return tuple(f for f in self.text_files if f.path.lower().endswith(".md"))

    def scripts(self) -> tuple[TextFile | CodeBlock, ...]:
        """Script files by extension plus the fenced blocks tagged as code (spec 5.3)."""
        files = tuple(f for f in self.text_files if f.path.lower().endswith(SCRIPT_EXTENSIONS))
        blocks = tuple(b for b in self.code_blocks if b.language in CODE_LANGUAGES)
        return files + blocks

    def file_at(self, path: str) -> TextFile | None:
        for f in self.text_files:
            if f.path == path:
                return f
        return None

    @property
    def files_scanned(self) -> int:
        return len(self.text_files) + len(self.binary_files)
