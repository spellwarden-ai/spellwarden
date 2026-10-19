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
_FENCE = re.compile(r"^(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)\s*$")


@dataclass(frozen=True)
class TextFile:
    path: str
    text: str
    lines: tuple[str, ...]


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
        return tuple(self.text.splitlines())


def _decode(content: bytes) -> str | None:
    """UTF-8 with replacement; `None` (binary) when too large or too damaged."""
    if len(content) > TEXT_MAX:
        return None
    text = content.decode("utf-8", errors="replace")
    if content and text.count("\ufffd") > len(content) * REPLACEMENT_SHARE:
        return None
    if b"\x00" in content:
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

    for number, line in enumerate(lines, start=1):
        match = _FENCE.match(line.strip())
        if fence is None:
            if match:
                fence, width = match.group(1)[0], len(match.group(1))
                language, start, body = match.group(2).lower(), number + 1, []
            continue
        # CommonMark: a closing fence repeats the opening character, is at least as long and has no info string.
        if match and match.group(1)[0] == fence and len(match.group(1)) >= width and not match.group(2):
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
            lines = tuple(text.splitlines())
            texts.append(TextFile(path, text, lines))
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
