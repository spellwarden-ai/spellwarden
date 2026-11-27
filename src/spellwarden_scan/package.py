"""What skill rules see (spec 5.3): decoded text files, binary files, the
fenced code blocks of every Markdown file, the metadata and the executable
paths. Built once per scan."""
from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from functools import cached_property

from spellwarden_scan import normalise
from spellwarden_scan.deadline import Lines, Meter
from spellwarden_scan.frontmatter import metadata_of
from spellwarden_scan.model import Metadata

# 1.22.0 (P6-4 spec 6.7): text is read up to 10 MiB, the command's `FILE_MAX` and the archive reader's `max_file`; a larger file
# whose first `TEXT_HEAD` bytes pass the text test is `TextLimit`, never a binary file that no text rule reads
TEXT_MAX = 10 * 2**20
TEXT_HEAD = 2**20
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


_NEWLINE = re.compile(r"\r\n|\r|\n")


def split_lines(text: str) -> tuple[str, ...]:
    """The file's lines as CommonMark and an editor number them: ended by `\\r\\n`, `\\r` or `\\n`, nothing
    else. `str.splitlines()` also breaks at `\\x0b`, `\\x0c`, `\\x1c`-`\\x1e`, `\\x85`, U+2028 and U+2029,
    which shifts every line number after one of them (spec 5.3: line numbers are the file's)."""
    lines = _NEWLINE.split(text)
    if lines and lines[-1] == "":
        lines.pop()
    return tuple(lines)


@dataclass(frozen=True)
class TextFile:
    path: str
    text: str
    lines: tuple[str, ...]
    head: bytes = b""  # the raw first eight bytes: SW-SKL-010 reads magic numbers here, never from re-encoded text
    # 1.27.0 (scan feedback fixes spec 5.3): listed executable and not read as Markdown, so the script rules read it whatever
    # its name; false for an executable Markdown file, whose fenced blocks are its scripts
    mode_script: bool = False


def is_script_file(unit: TextFile) -> bool:
    """1.27.0 (scan feedback fixes spec 5.3): a script by its extension, or by its executable mode when it is not read as
    Markdown (`TextFile.mode_script`)."""
    return unit.mode_script or unit.path.lower().endswith(SCRIPT_EXTENSIONS)


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
    # 1.24.0 (speed and deadline spec 7.3): the scan's time meter; with one, `lines` ticks it as it is iterated
    meter: Meter | None = field(default=None, compare=False, repr=False)

    # built on each read and dropped after it, never kept: a package of many small blocks held for its whole life cost 63 per cent
    # more peak memory with a deadline (r1:F1); a small `Lines` is cheap to build (one tick, no cuts, deadline.py)
    @property
    def lines(self) -> tuple[str, ...]:
        lines = split_lines(self.text)
        return lines if self.meter is None else Lines(lines, self.meter, self.path)

    @cached_property
    def line_count(self) -> int:
        """The number of `lines`, worked out once and kept as one number: the readers that only count a block's lines (the fenced
        line sets, a folded block's slice) build no `Lines` for it."""
        return len(split_lines(self.text))


class TextLimit(Exception):
    """1.22.0 (P6-4 spec 6.7.2): a text file over `TEXT_MAX`, which the engine does not read. `path` names the file and `size` is
    its size in bytes. Content left unread is the caller's error to report, never a pass: `scan_skill_package` returns no finding
    of such a package."""

    def __init__(self, path: str, size: int) -> None:
        super().__init__(f"{path} is {size} bytes of text, over the {TEXT_MAX} bytes the rules read")
        self.path = path
        self.size = size


def _decode(content: bytes) -> str | None:
    """UTF-8 with replacement; `None` (binary) when too damaged. The caller checks the size first (`TEXT_MAX`)."""
    text = content.decode("utf-8", errors="replace")
    if content and text.count("\ufffd") > len(content) * REPLACEMENT_SHARE:
        return None
    return text


def _code_blocks(path: str, lines: tuple[str, ...], meter: Meter | None = None) -> list[CodeBlock]:
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
        blocks.append(CodeBlock(path, language, "\n".join(body), start, meter))

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
                 code_blocks: tuple[CodeBlock, ...], metadata: Metadata, executable_paths: frozenset[str],
                 markdown_paths: frozenset[str] = frozenset(), shared: dict | None = None, meter: Meter | None = None) -> None:
        self.root = root
        self.text_files = text_files
        self.binary_files = binary_files
        self.code_blocks = code_blocks
        self.metadata = metadata
        self.executable_paths = executable_paths
        self.markdown_paths = markdown_paths
        # 1.24.0 (speed and deadline spec 6.2, F1): what rules compute once for this subject, a package or one of its views and
        # never two of them, and read again; the rule that needs a value fills it in the first time
        self.shared: dict = {} if shared is None else shared
        # 1.24.0 (spec 7.3): the scan's time meter, or None; with one, the lines of every file and code block tick it
        self.meter = meter

    @classmethod
    def build(cls, files: Mapping[str, bytes], *, root: str = "", executable_paths: Collection[str] = (),
              markdown_paths: Collection[str] = frozenset(), meter: Meter | None = None) -> Package:
        """`markdown_paths` (1.13.0, Phase 3 batch 1 spec 10.3) are paths read as Markdown whatever their suffix: a Cursor `.mdc`
        rule, `.cursorrules` and `.windsurfrules` hold instructions but do not end in `.md`, so without this no injection or
        concealment check and no code block would reach them. The default leaves every existing call as it was.
        `meter` (1.24.0) is the scan's time meter: the build looks at the clock before each file, and the lines of every file and
        code block tick it."""
        if meter is not None:
            meter.stage = "reading"
        root = root.strip("/")
        markdown = frozenset(markdown_paths)
        prefix = f"{root}/" if root else ""
        texts: list[TextFile] = []
        binaries: list[BinaryFile] = []
        blocks: list[CodeBlock] = []
        # Only the executable entries under `root` belong to this package: a sibling directory's binaries are not its finding.
        kept = frozenset(path for path in executable_paths if not prefix or path.startswith(prefix))
        for path in sorted(files):
            if prefix and not path.startswith(prefix):
                continue
            if meter is not None:
                meter.check(path)
            content = files[path]
            if len(content) > TEXT_MAX:
                if _decode(content[:TEXT_HEAD]) is not None:
                    raise TextLimit(path, len(content))
                binaries.append(BinaryFile(path, content[:8], len(content)))
                continue
            text = _decode(content)
            if text is None:
                binaries.append(BinaryFile(path, content[:8], len(content)))
                continue
            lines = split_lines(text)
            if meter is not None:
                lines = Lines(lines, meter, path)
            read_as_markdown = path.lower().endswith(".md") or path in markdown
            texts.append(TextFile(path, text, lines, content[:8], path in kept and not read_as_markdown))
            if read_as_markdown:
                blocks.extend(_code_blocks(path, lines, meter))
        return cls(root, tuple(texts), tuple(binaries), tuple(blocks), metadata_of(files, root), kept, markdown, meter=meter)

    def instructions(self) -> tuple[TextFile, ...]:
        return tuple(f for f in self.text_files if f.path.lower().endswith(".md") or f.path in self.markdown_paths)

    def scripts(self) -> tuple[TextFile | CodeBlock, ...]:
        """Script files by extension or by executable mode (a file read as Markdown never by its mode), plus the fenced blocks
        tagged as code (spec 5.3; executable mode since 1.27.0, scan feedback fixes spec 5.3)."""
        files = tuple(f for f in self.text_files if is_script_file(f))
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

    def views(self, steps: Collection[str]) -> tuple[View, ...]:
        """1.22.0 (P6-4 spec 6.5.4, 6.5.5): the folded view, then the decoded view, each only when it holds a file; none for a
        package whose text the steps leave unchanged, the common case. With a time meter (1.24.0) the build looks at the clock
        before each file and every loop over a file's lines ticks it."""
        meter = self.meter
        if meter is not None:
            meter.stage = "normalising"
        blocks: dict[str, list[CodeBlock]] = {}
        for block in self.code_blocks:
            blocks.setdefault(block.path, []).append(block)
        folded_files: list[TextFile] = []
        folded_blocks: list[CodeBlock] = []
        decoded_files: list[TextFile] = []
        decoded_blocks: list[CodeBlock] = []
        decoded_lines: dict[str, tuple[int, ...]] = {}
        for unit in self.text_files:
            if meter is not None:
                meter.check(unit.path)
            folded = tuple(normalise.fold(line, steps) for line in unit.lines)
            own = blocks.get(unit.path, [])
            lines = unit.lines  # a line that no step changed is the line as built; `folded` equals it
            if folded != unit.lines:
                lines = folded if meter is None else Lines(folded, meter, unit.path)
                folded_files.append(TextFile(unit.path, "\n".join(folded), lines, unit.head, unit.mode_script))
                for block in own:  # the original boundaries, never recomputed from folded text
                    start = block.first_line - 1
                    body = folded[start:start + block.line_count]
                    folded_blocks.append(CodeBlock(block.path, block.language, "\n".join(body), block.first_line, meter))
            shadow = _shadow(unit, lines, own, steps, markdown=self._is_markdown(unit.path), meter=meter)
            if shadow is not None:
                text_file, origin = shadow
                decoded_files.append(text_file)
                decoded_lines[unit.path] = origin
                if self._is_markdown(unit.path):
                    decoded_blocks.extend(_code_blocks(unit.path, text_file.lines, meter))
        found: list[View] = []
        if folded_files:
            found.append(View(self, tuple(folded_files), tuple(folded_blocks), {}))
        if decoded_files:
            found.append(View(self, tuple(decoded_files), tuple(decoded_blocks), decoded_lines))
        return tuple(found)

    def _is_markdown(self, path: str) -> bool:
        return path.lower().endswith(".md") or path in self.markdown_paths


SEPARATOR_LINES = 4  # empty lines after each payload: no window counted in lines or commands reaches the next (spec 6.5.5)


def _longest_backticks(text: str) -> int:
    return max((len(run) for run in re.findall(r"`+", text)), default=0)


def _open_fence(lines: list[str]) -> str | None:
    """The closing fence a block left open at the end of `lines` needs, or None, read as `_code_blocks` reads fences."""
    fence: str | None = None
    width = indent = 0
    for line in lines:
        if fence is None:
            opener = _OPENER.match(line.strip())
            if opener:
                fence, width, indent = opener.group(1)[0], len(opener.group(1)), _indent(line)
            continue
        closer = _CLOSER.match(line.strip())
        if closer and closer.group(1)[0] == fence and len(closer.group(1)) >= width and _indent(line) < indent + 4:
            fence = None
    return None if fence is None else fence * width


def _shadow(unit: TextFile, folded: tuple[str, ...], blocks: list[CodeBlock], steps: Collection[str], *,
            markdown: bool, meter: Meter | None = None) -> tuple[TextFile, tuple[int, ...]] | None:
    """The decoded view's file for `unit` (spec 6.5.5): the payloads of its lines in line order, each followed by
    `SEPARATOR_LINES` empty lines, and for every line of it the line of `unit` whose token held the payload laid out there.
    None when no line of `unit` holds a payload."""
    fenced = {block.first_line + offset: block for block in blocks for offset in range(block.line_count)}
    out: list[str] = []
    origin: list[int] = []
    for number, line in enumerate(folded, start=1):
        for payload in normalise.payloads(line, steps):
            laid = list(split_lines(payload)) or [""]
            block = fenced.get(number)
            if block is not None:
                fence = "`" * max(3, _longest_backticks(payload) + 1)
                laid = [fence + block.language, *laid, fence]
            elif markdown:
                closing = _open_fence(laid)
                if closing is not None:
                    laid.append(closing)
            laid += [""] * SEPARATOR_LINES
            out.extend(laid)
            origin.extend([number] * len(laid))
    if not out:
        return None
    lines = tuple(out)
    text = "\n".join(lines)
    return (TextFile(unit.path, text, lines if meter is None else Lines(lines, meter, unit.path), unit.head, unit.mode_script),
            tuple(origin))


class View(Package):
    """A normalised reading of a package (P6-4 spec 6.5): the folded view holds each changed text file with every line folded,
    the decoded view a shadow file of payloads per file. `origin` is the package as built; `metadata`, `binary_files`,
    `executable_paths`, `markdown_paths`, `root` and `file_at` answer from it (spec 6.5.7), so a view never parses a front matter
    the original pass did not."""

    def __init__(self, origin: Package, text_files: tuple[TextFile, ...], code_blocks: tuple[CodeBlock, ...],
                 lines: Mapping[str, tuple[int, ...]]) -> None:
        super().__init__(origin.root, text_files, origin.binary_files, code_blocks, origin.metadata, origin.executable_paths,
                         origin.markdown_paths, meter=origin.meter)
        self.origin = origin
        self._lines = dict(lines)

    def file_at(self, path: str) -> TextFile | None:
        return self.origin.file_at(path)

    def original_line(self, path: str, line: int) -> int | None:
        """The line of the original file that line `line` of this view's file `path` stands for: the same number in the
        folded view; in the decoded view the line whose token held the payload (a separator or a closing fence maps to the
        payload before it). None for a line the file does not have."""
        mapping = self._lines.get(path)
        if mapping is None:
            return line
        return mapping[line - 1] if 1 <= line <= len(mapping) else None
