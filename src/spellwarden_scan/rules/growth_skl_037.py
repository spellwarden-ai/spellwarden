"""SW-SKL-037: executable downloaded from a moving reference and run without an integrity check.

Read over the skill's scripts and fenced code blocks (`Package.scripts()`):

* shell and PowerShell: a download written to a file (`curl -o/-O` or a redirect, `wget -O`, `Invoke-WebRequest
  -OutFile`, `DownloadFile`) or piped into `tar -x` with a bin directory as target, followed in the same command or in
  the next five commands by an execute step on that file (`chmod +x`, a mode with an execute bit, a move or extraction
  into a bin directory, a direct run or a run through an interpreter);
* Python and JavaScript: a download written to a file, followed within twelve lines by an execute-mode `chmod` or a
  spawn of that file;
* a `git clone` of the default branch (no `--branch <tag>`, no later checkout of a commit) followed within five
  commands by an install or a run inside the clone.

The URL is a moving reference: `/releases/latest/`, `/releases/download/latest/`, a raw default-branch path, a branch
archive, or a path with no version segment at all. The unit is quiet when it checks integrity (a checksum verified, a
hash compared to a value, a signature verified). Data files, `/dev/null` and package-manager installs have no
execute step on a download and stay quiet. The finding is at the download's line.

Commands are cut once, left to right, at unquoted `;`, `&&`, `||`, `&` and newlines, and each window is bounded, so a
long line is read in linear time. The module is registered by the rule set, not here."""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from spellwarden_scan.evidence import excerpt, fingerprint
from spellwarden_scan.model import Finding, Location
from spellwarden_scan.package import SHELL_LANGUAGES, CodeBlock, Package, TextFile

RULE_ID = "SW-SKL-037"
TITLE = "Executable downloaded from a moving reference and run without an integrity check"
SEVERITY = "medium"
OWASP = ("ASI04", "ASI05")
NIST = ("SR-3", "SI-7")
MALICIOUS = False

_SHELL_WINDOW = 5  # commands after the download that may hold its execute step
_PROGRAM_WINDOW = 12  # non-blank lines of a Python or JavaScript script
_PROGRAM_LEAD = 6  # lines before the URL that may open the destination file
_PER_PACKAGE = 25
_URLS_PER_LINE = 8
_ARG_SPAN = 600  # characters of a call's arguments that are read

_SHELL_EXTENSIONS = (".sh", ".bash", ".zsh", ".ps1")
_PYTHON_EXTENSIONS = (".py",)
_JS_EXTENSIONS = (".js", ".mjs", ".ts")
_JS_LANGUAGES = ("js", "javascript", "ts", "typescript")

_DEFAULT_BRANCHES = frozenset({"main", "master", "head", "trunk", "develop", "dev", "latest", "nightly"})
_DATA_SUFFIXES = (".json", ".csv", ".tsv", ".txt", ".md", ".html", ".xml", ".yaml", ".yml", ".toml", ".png", ".jpg", ".jpeg",
                  ".gif", ".svg", ".webp", ".pdf", ".gguf", ".safetensors", ".onnx", ".pt", ".pth", ".ckpt", ".h5", ".npy",
                  ".npz", ".parquet", ".pkl", ".sig", ".asc", ".sha256", ".sha512", ".pem", ".log", ".mp3", ".mp4", ".wav")
_NULL_TARGETS = frozenset({"/dev/null", "nul", "$null", "-"})

_WRAPPERS = frozenset({"sudo", "doas", "exec", "nohup", "time", "command", "env", "start-process", "start", "&", "call"})
_CURL_LIKE = frozenset({"curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm", "start-bitstransfer"})
_OUT_OPTIONS = frozenset({"-o", "--output", "-outfile", "-destination", "--output-document"})
_INTERPRETERS = frozenset({"sh", "bash", "zsh", "dash", "python", "python3", "py", "node", "ruby", "perl", "pwsh", "powershell"})
_PLACERS = frozenset({"mv", "cp", "install", "ln", "move", "move-item", "copy", "copy-item"})
_EXTRACTORS = frozenset({"tar", "unzip", "7z", "7za", "bsdtar"})
_CLONE_RUNNERS = frozenset({
    "pip", "pip3", "python", "python3", "py", "node", "npm", "npx", "yarn", "pnpm", "make", "bash", "sh", "zsh", "cargo", "go",
    "cmake", "ruby", "gem", "bundle", "uv", "uvx", "pipx", "poetry", "pwsh", "powershell",
})
_CLONE_VALUE_OPTIONS = frozenset({
    "-b", "--branch", "--depth", "-o", "--origin", "-c", "--config", "--reference", "--separate-git-dir", "--template",
    "-j", "--jobs", "--filter", "--shallow-since", "--shallow-exclude", "-u", "--upload-pack", "--server-option", "--revision",
})
_HASH_TOOLS = frozenset({"sha256sum", "sha512sum", "sha384sum", "shasum", "b2sum", "get-filehash", "openssl", "certutil"})
_COMPARISONS = frozenset({"=", "==", "!=", "-eq", "-ne", "-ceq", "-cne", "diff", "cmp", "grep", "test", "[", "[["})
_UNIT_COMPARISONS = frozenset({"=", "==", "!=", "-eq", "-ne", "-ceq", "-cne", "diff", "cmp"})
_FETCH_MARKERS = ("urlretrieve", "urlopen", "requests.", "httpx.", "urllib", "fetch(", "https.get", "http.get", "axios", "got(",
                  "got.", ".get(", "request(", "download", "wget", "curl")
_SPAWN_MARKERS = ("subprocess.", "os.system", "os.exec", "os.spawn", "os.startfile", "popen", "check_call", "check_output",
                  "execsync", "execfile", "spawn(", "spawnsync", "exec(", "child_process", "shell.openpath")
_HASH_MARKERS = ("hexdigest", ".digest(", "sha256", "sha512", "checksum", "createhash")
_COMPARE_MARKERS = ("==", "!=", "compare_digest", "assert ", "timingsafeequal", ".equals(", "===", "!==")


@dataclass(frozen=True, slots=True)
class _Command:
    line: int
    text: str
    stages: tuple[tuple[str, ...], ...]  # the cleaned tokens of each `|` stage


def _clean(token: str) -> str:
    token = token.strip("\"'`;")
    if token.startswith("${") and token.endswith("}"):
        return "$" + token[2:-1]
    if token.startswith("$("):
        token = token[2:]
    return token.strip("\"'`;(){}[]")


def _basename(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _normal(path: str) -> str:
    text = path.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def _same_path(left: str, right: str) -> bool:
    a, b = _normal(left), _normal(right)
    if not a or not b or a.startswith("-") or b.startswith("-"):
        return False
    return a == b or _basename(a) == _basename(b)


def _bin_dir(path: str) -> bool:
    parts = _normal(path).lower().split("/")
    return "bin" in parts or "sbin" in parts


def _split_commands(command: str) -> Iterator[str]:
    """The command cut at unquoted `;`, `&&`, `||`, `&` and newlines; a single `|` stays, spaced, as a stage mark."""
    quote = ""
    start = 0
    out: list[str] = []
    index = 0
    size = len(command)
    while index < size:
        char = command[index]
        if quote:
            if char == "\\" and quote == '"':
                index += 1
            elif char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "\\":
            index += 1
        elif char in ";\n" or (char == "&" and command[index - 1:index] not in (">", "<")):
            out.append(command[start:index])
            start = index + 1
            if char == "&" and command[index + 1:index + 2] == "&":
                index += 1
                start = index + 1
        elif char == "|":
            if command[index + 1:index + 2] == "|":
                out.append(command[start:index])
                index += 1
                start = index + 1
            else:
                out.append(command[start:index] + " | ")
                start = index + 1
        index += 1
    out.append(command[start:])
    # Pieces ended by a stage mark belong to one command: glue them back.
    pending = ""
    for piece in out:
        if piece.endswith(" | "):
            pending += piece
            continue
        text = pending + piece
        pending = ""
        if text.strip():
            yield text
    if pending.strip():
        yield pending


def _commands(unit: TextFile | CodeBlock, logical_commands) -> Iterator[_Command]:
    for _path, number, text in logical_commands(unit):
        stripped = text.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith(("$ ", "> ")):
            stripped = stripped[2:]
        for piece in _split_commands(stripped):
            stages: list[tuple[str, ...]] = []
            current: list[str] = []
            for token in piece.split():
                if token == "|":
                    stages.append(tuple(current))
                    current = []
                    continue
                cleaned = _clean(token)
                if cleaned:
                    current.append(cleaned)
            stages.append(tuple(current))
            stages = [stage for stage in stages if stage]
            if stages:
                yield _Command(number, piece.strip(), tuple(stages))


def _head(stage: tuple[str, ...]) -> int:
    """The index of the command word of a stage: wrappers (`sudo`, `exec`, ...), their flags and `VAR=value` skipped."""
    index = 0
    size = len(stage)
    while index < size:
        word = stage[index].lower()
        if word in _WRAPPERS or (word.startswith("-") and index) or ("=" in word and not word.startswith(("/", "-", "."))
                                                                     and word.split("=", 1)[0].replace("_", "").isalnum()):
            index += 1
            continue
        break
    return min(index, size - 1)


def _name(stage: tuple[str, ...]) -> tuple[str, int]:
    index = _head(stage)
    name = _basename(stage[index]).lower()
    return (name[:-4] if name.endswith(".exe") else name), index


# --- the moving reference ---------------------------------------------------------------------------------------

def _version_like(segment: str) -> bool:
    low = segment.lower()
    if "$" in low or "{" in low or "<" in low or "%" in low:
        return True  # a variable stands for the version: pinned by whoever sets it
    for index in range(1, len(low) - 1):
        if low[index] == "." and low[index - 1].isdigit() and low[index + 1].isdigit():
            return True
    if len(low) > 1 and low[0] == "v" and low[1].isdigit():
        return True
    for marker in ("-v", "_v", "@v"):
        at = low.find(marker)
        while at != -1:
            if low[at + 2:at + 3].isdigit():
                return True
            at = low.find(marker, at + 1)
    if len(low) >= 7 and all(char in "0123456789abcdef" for char in low) and any(char.isdigit() for char in low):
        return True
    return len(low) >= 8 and low[:4].isdigit() and low[4] in "-._" and low[5:7].isdigit()


def _moving(url: str) -> bool:
    text = url.split("#", 1)[0].split("?", 1)[0]
    scheme_end = text.find("://")
    if scheme_end == -1:
        return False
    host, _, path = text[scheme_end + 3:].partition("/")
    host = host.rsplit("@", 1)[-1].split(":", 1)[0].lower()
    segments = [part for part in path.split("/") if part]
    if not segments or "." not in host:
        return False
    lows = [part.lower() for part in segments]
    for index, part in enumerate(lows):
        if part == "releases" and index + 1 < len(lows):
            after = lows[index + 1]
            if after == "latest" or (after == "download" and index + 2 < len(lows) and lows[index + 2] == "latest"):
                return True
        if part == "raw" and index + 1 < len(lows) and lows[index + 1] in ("main", "master", "head"):
            return True
        if part == "archive" and index + 1 < len(lows):
            ref = lows[index + 3] if lows[index + 1:index + 3] == ["refs", "heads"] and index + 3 < len(lows) else lows[index + 1]
            if ref.split(".", 1)[0] in ("main", "master", "head"):
                return True
    if host == "raw.githubusercontent.com":
        ref = lows[2:3]
        if ref and ref[0] in ("main", "master", "head"):
            return True
        if lows[2:4] == ["refs", "heads"] and lows[4:5] and lows[4] in ("main", "master", "head"):
            return True
        return False
    return not any(_version_like(part) for part in segments)


# --- shell downloads ---------------------------------------------------------------------------------------------

def _first_url(tokens: tuple[str, ...]) -> str:
    for token in tokens:
        if token.lower().startswith(("http://", "https://")):
            return token
    return ""


def _download_target(stage: tuple[str, ...], name: str, index: int, url: str) -> str | None:
    """The file a curl/wget/PowerShell stage writes, `""` when it writes to the terminal or a pipe, `None` when the
    target can be ignored (`/dev/null`)."""
    out = ""
    remote_name = name == "wget"  # wget names the file after the URL by default
    redirect = ""
    size = len(stage)
    position = index + 1
    while position < size:
        token = stage[position]
        low = token.lower()
        following = stage[position + 1] if position + 1 < size else ""
        if low in _OUT_OPTIONS:
            out = following
            position += 2
            continue
        if low.startswith("--output="):
            out = token.split("=", 1)[1]
        elif low.startswith("--output-document="):
            out = token.split("=", 1)[1]
        elif token in ("--remote-name", "-O") and name == "curl":
            remote_name = True
        elif name == "curl" and token.startswith("-") and not token.startswith("--") and token[1:].isalpha():
            if token.endswith("o"):
                out = following
                position += 2
                continue
            if "O" in token:
                remote_name = True
        elif name == "wget" and token.startswith("-") and not token.startswith("--") and token[1:].rstrip("-").isalpha() \
                and token.endswith(("O", "O-")):
            out = "-" if token.endswith("-") else following
            position += 1 if token.endswith("-") else 2
            continue
        elif token in (">", ">>"):
            redirect = following
            position += 2
            continue
        elif token.startswith((">", ">>")) and not token[:2].strip(">").isdigit():
            redirect = token.lstrip(">")
        position += 1
    target = out or redirect
    if not target and remote_name and url:
        target = _basename(url.split("#", 1)[0].split("?", 1)[0])
    if target.lower() in _NULL_TARGETS:
        return None if target != "-" else ""
    return target


def _data_file(target: str) -> bool:
    return target.lower().endswith(_DATA_SUFFIXES)


def _tar_to_bin(stage: tuple[str, ...]) -> bool:
    extracts = False
    directory = False
    for position, token in enumerate(stage[1:], start=1):
        low = token.lower()
        if token == "--extract" or (token.startswith("-") and not token.startswith("--") and "x" in token[1:] and token[1:].isalpha()) \
                or (position == 1 and token.isalpha() and "x" in token and set(token) <= set("xzfvjJpCOa")):
            extracts = True
        if low.startswith("--directory="):
            directory = directory or _bin_dir(token.split("=", 1)[1])
        elif token in ("-C", "--directory") and position + 1 < len(stage):
            directory = directory or _bin_dir(stage[position + 1])
        elif token.startswith("-C") and len(token) > 2:
            directory = directory or _bin_dir(token[2:])
        elif token.startswith("-") and not token.startswith("--") and token.endswith("C") and position + 1 < len(stage):
            directory = directory or _bin_dir(stage[position + 1])
    return extracts and directory


def _mode_executable(token: str) -> bool:
    low = token.lower()
    if "+" in low and "x" in low.split("+", 1)[1]:
        return True
    if low.isdigit() and 3 <= len(low) <= 4 and all(char in "01234567" for char in low):
        return bool(int(low, 8) & 0o111)
    return False


def _key(path: str) -> str:
    """What `_same_path` compares: the base name of the normalised path; empty for an option or nothing."""
    normal = _normal(path)
    return "" if not normal or normal.startswith("-") else _basename(normal)


def _run_names(stage: tuple[str, ...]) -> frozenset[str]:
    """The keys (`_key`) of every file this stage makes executable or runs: the arguments of an execute-mode `chmod`,
    the command itself, the script an interpreter runs, and what is moved or extracted into a bin directory. Worked out
    once per stage, so a download is matched against the stages after it by a set lookup (linear in the stages)."""
    name, index = _name(stage)
    rest = stage[index + 1:]
    names: set[str] = set()
    if name == "chmod":
        arguments = [token for token in rest if not token.startswith("-") or token.startswith(("-x", "+x"))]
        modes = [token for token in arguments if _mode_executable(token)]
        if modes:
            names.update(_key(token) for token in arguments if token not in modes)
        return frozenset(names - {""})
    # The command itself (`./tool`, `/opt/x/tool`, `tool`): `_same_path` matches its base name, and a bare name equal
    # to the download's base name runs it too.
    names.add(_key(stage[index]))
    if name in _INTERPRETERS:
        for token in rest:
            if not token.startswith("-"):
                names.add(_key(token))
                break
    elif name in _PLACERS or name in _EXTRACTORS:
        if any(_bin_dir(token) for token in rest):
            names.update(_key(token) for token in rest)
    return frozenset(names - {""})


def _runs_target(stage: tuple[str, ...], target: str) -> bool:
    key = _key(target)
    return bool(key) and key in _run_names(stage)


@dataclass(frozen=True)
class _Facts:
    """Per command, worked out once in one pass: the last stage that runs or makes executable each name, the last
    stage that extracts into a bin directory (-1 when none), and every name its stages run. A download at stage `i` is
    run later in its command when the name's last stage is after `i`; no per-stage set is built, so the work stays
    linear in the command's tokens whatever the number of stages."""
    last_run: dict[str, int]
    last_tar: int
    names: frozenset[str]


def _facts(command: _Command) -> _Facts:
    last_run: dict[str, int] = {}
    last_tar = -1
    for number, stage in enumerate(command.stages):
        for name in _run_names(stage):
            last_run[name] = number
        if _name(stage)[0] in _EXTRACTORS and _tar_to_bin(stage):
            last_tar = number
    return _Facts(last_run, last_tar, frozenset(last_run))


def _verifies(commands: list[_Command]) -> bool:
    """The unit checks what it downloaded: a checksum verified or compared to a value, or a signature verified."""
    hashed = compared = False
    for command in commands:
        flat = [token for stage in command.stages for token in stage]
        lows = [token.lower() for token in flat]
        names = {_basename(token.rsplit("$(", 1)[-1].lstrip("`")).lower() for token in lows}  # `X=$(sha256sum f)`
        # A digest taken in one command and compared to a value in another (`ACTUAL=$(sha256sum f)`, `[ "$ACTUAL" != ... ]`).
        hashed = hashed or bool(names & _HASH_TOOLS)
        compared = compared or any(token in _UNIT_COMPARISONS for token in lows)
        if hashed and compared:
            return True
        if names & _HASH_TOOLS:
            if "-c" in lows or "--check" in lows or "-check" in lows or "-compare" in lows:
                return True
            if any(token in _COMPARISONS for token in lows) or any(len(token) >= 64 and all(c in "0123456789abcdef" for c in token)
                                                                    for token in lows):
                return True
            if any(token.startswith(("!=", "==")) or token.endswith(("=", "==")) for token in lows):
                return True
        if names & {"gpg", "gpg2", "gpgv"} and ("--verify" in lows or "gpgv" in names):
            return True
        if "cosign" in names and any(token.startswith("verify") for token in lows):
            return True
        if "minisign" in names and any(token.startswith("-V") for token in flat):
            return True
        if "signify" in names and "-V" in flat:
            return True
        if names & {"slsa-verifier"} or (names & {"gh"} and "verify" in lows):
            return True
        if "git" in names and ({"verify-commit", "verify-tag"} & set(lows) or ("tag" in lows and "-v" in lows)):
            return True
    return False


def _clone(stage: tuple[str, ...]) -> tuple[str, bool] | None:
    """`(directory, pinned)` of a `git clone` stage, `None` when the stage is something else."""
    name, index = _name(stage)
    if name != "git":
        return None
    position = index + 1
    while position < len(stage) and stage[position].startswith("-"):
        position += 2 if stage[position] in ("-C", "-c") else 1
    if position >= len(stage) or stage[position] != "clone":
        return None
    branch = ""
    positional: list[str] = []
    position += 1
    while position < len(stage):
        token = stage[position]
        if token in ("-b", "--branch") and position + 1 < len(stage):
            branch = stage[position + 1]
            position += 2
            continue
        if token.startswith("--branch="):
            branch = token.split("=", 1)[1]
        elif token in _CLONE_VALUE_OPTIONS:
            position += 2
            continue
        elif not token.startswith("-"):
            positional.append(token)
        position += 1
    if not positional or not ("://" in positional[0] or "@" in positional[0]):
        return None
    directory = positional[1] if len(positional) > 1 else _basename(positional[0]).removesuffix(".git")
    pinned = bool(branch) and branch.lower() not in _DEFAULT_BRANCHES
    return directory.rstrip("/"), pinned


def _commit_like(token: str) -> bool:
    low = token.lower()
    if 7 <= len(low) <= 64 and all(char in "0123456789abcdef" for char in low) and any(char.isdigit() for char in low):
        return True
    return len(low) > 1 and low[0] == "v" and low[1].isdigit()


def _pins_commit(command: _Command) -> bool:
    for stage in command.stages:
        name, index = _name(stage)
        if name == "git" and any(token in ("checkout", "switch", "reset") for token in stage[index + 1:index + 4]):
            if any(_commit_like(token) for token in stage[index + 1:]):
                return True
    return False


def _clone_runs(stage: tuple[str, ...], directory: str, inside: bool) -> bool:
    name, index = _name(stage)
    head = stage[index]
    runner = name in _CLONE_RUNNERS or head.startswith(("./", ".\\")) or name.endswith((".sh", ".ps1"))
    if not runner or name == "git":
        return False
    if inside:
        return True
    prefix = _normal(directory).rstrip("/") + "/"
    for token in stage[index:]:
        normal = _normal(token)
        if normal.startswith(prefix) or normal == prefix.rstrip("/"):
            return True
    return False


def _stage_hit(command: _Command, number: int, facts: _Facts, window_names: frozenset[str]) -> bool:
    """Whether stage `number` of `command` is a moving download that a later stage, or a command of the window, makes
    executable or runs (every later stage is read: no position limit, and the lookups are set lookups)."""
    stage = command.stages[number]
    name, index = _name(stage)
    if name in _CURL_LIKE:
        url = _first_url(stage)
        if not url or not _moving(url):
            return False
        target = _download_target(stage, "curl" if name == "start-bitstransfer" else name, index, url)
        if target is None:
            return False
        if target == "":
            return facts.last_tar > number
        if _data_file(target):
            return False
        key = _key(target)
        return bool(key) and (facts.last_run.get(key, -1) > number or key in window_names)
    return False


def _clone_hit(command: _Command, window: list[_Command], pinned_later: bool) -> bool:
    for stage in command.stages:
        clone = _clone(stage)
        if clone is None:
            continue
        directory, pinned = clone
        return not (pinned or pinned_later) and _clone_executes(window, directory)
    return False


def _shell_hits(commands: list[_Command]) -> Iterator[tuple[int, str]]:
    if _verifies(commands):
        return
    pinned_later = [False] * (len(commands) + 1)  # a commit is checked out in some command after this one
    for position in range(len(commands) - 1, -1, -1):
        pinned_later[position] = pinned_later[position + 1] or _pins_commit(commands[position])
    facts = [_facts(command) for command in commands]
    for position, command in enumerate(commands):
        window = commands[position + 1:position + 1 + _SHELL_WINDOW]
        # Each command is in at most `_SHELL_WINDOW` windows, so these unions stay linear in the unit's size.
        window_names = frozenset().union(*(fact.names for fact in facts[position + 1:position + 1 + _SHELL_WINDOW]))
        if "downloadfile(" in command.text.lower():
            hit = _download_file_call(command, window_names)
        else:
            hit = any(_stage_hit(command, number, facts[position], window_names) for number in range(len(command.stages)))
            hit = hit or _clone_hit(command, window, pinned_later[position + 1])
        if hit:
            yield command.line, command.text


def _download_file_call(command: _Command, window_names: frozenset[str]) -> bool:
    low = command.text.lower()
    at = low.find("downloadfile(")
    arguments = _call_args(command.text, at + len("downloadfile("))
    if len(arguments) < 2:
        return False
    url, target = arguments[0].strip("'\" "), arguments[1].strip("'\" ")
    if not url.lower().startswith(("http://", "https://")) or not _moving(url) or _data_file(target):
        return False
    key = _key(target)
    return bool(key) and key in window_names


def _clone_executes(window: list[_Command], directory: str) -> bool:
    inside = False
    for item in window:
        for stage in item.stages:
            name, index = _name(stage)
            if name in ("cd", "pushd", "set-location") and index + 1 < len(stage):
                inside = _same_path(stage[index + 1], directory) and _normal(stage[index + 1]).rstrip("/") == _normal(directory)
                continue
            if _clone_runs(stage, directory, inside):
                return True
    return False


# --- Python and JavaScript ---------------------------------------------------------------------------------------

def _call_args(text: str, start: int) -> list[str]:
    """The top-level arguments of the call whose `(` ends just before `start`; at most `_ARG_SPAN` characters are read."""
    arguments: list[str] = []
    depth = 0
    quote = ""
    begin = start
    stop = min(len(text), start + _ARG_SPAN)
    index = start
    while index < stop:
        char = text[index]
        if quote:
            if char == "\\":
                index += 1
            elif char == quote:
                quote = ""
        elif char in "'\"`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                arguments.append(text[begin:index].strip())
                return arguments
            depth -= 1
        elif char == "," and depth == 0:
            arguments.append(text[begin:index].strip())
            begin = index + 1
        index += 1
    arguments.append(text[begin:stop].strip())
    return arguments


def _urls(line: str) -> Iterator[str]:
    low = line.lower()
    seen = 0
    for scheme in ("https://", "http://"):
        at = low.find(scheme)
        while at != -1 and seen < _URLS_PER_LINE:
            end = at
            limit = min(len(line), at + 2000)
            while end < limit and line[end] not in "\"'` \t)(<>,;":
                end += 1
            yield line[at:end]
            seen += 1
            at = low.find(scheme, end)


def _words(expression: str) -> set[str]:
    words: set[str] = set()
    current: list[str] = []
    for char in expression[:_ARG_SPAN] + " ":
        if char.isalnum() or char in "_-":
            current.append(char)
            continue
        if len(current) >= 3:
            words.add("".join(current))
        current = []
    return words - {"path", "join", "str", "expanduser", "getcwd", "dirname", "pathlib", "tmpdir", "tempfile"}


def _mentions(line: str, words: set[str]) -> bool:
    return any(word in line for word in words)


def _exec_mode(argument: str) -> bool:
    low = argument.strip().strip("'\"").lower()
    if "s_ix" in low or "s_iexec" in low or "0o111" in low:
        return True
    if low.startswith("0o") and low[2:].isdigit() and all(char in "01234567" for char in low[2:]):
        return bool(int(low[2:], 8) & 0o111)
    if low.isdigit() and 3 <= len(low) <= 4 and all(char in "01234567" for char in low):
        return bool(int(low, 8) & 0o111)
    return False


def _write_targets(line: str) -> set[str] | None:
    """The words of the file a line writes a download to, an empty set when the file is not named, `None` when the line
    writes nothing."""
    low = line.lower()
    for marker in ("urlretrieve(",):
        at = low.find(marker)
        if at != -1:
            arguments = _call_args(line, at + len(marker))
            return _words(arguments[1]) if len(arguments) > 1 else set()
    for marker in ("createwritestream(", "writefilesync(", "writefile("):
        at = low.find(marker)
        if at != -1:
            arguments = _call_args(line, at + len(marker))
            return _words(arguments[0]) if arguments else set()
    at = low.find("open(")
    if at != -1:
        arguments = _call_args(line, at + len("open("))
        if len(arguments) > 1:
            mode = arguments[1].strip("'\" ").lower()
            if "w" in mode and "b" in mode:
                return _words(arguments[0])
    if ".write_bytes(" in low:
        at = low.find("path(")
        if at != -1:
            arguments = _call_args(line, at + len("path("))
            return _words(arguments[0]) if arguments else set()
        return set()
    return None


def _execute_line(line: str, words: set[str]) -> bool:
    low = line.lower()
    at = low.find("chmod")
    if at != -1:
        paren = low.find("(", at)
        if paren != -1:
            arguments = _call_args(line, paren + 1)
            if any(_exec_mode(argument) for argument in arguments) and (not words or _mentions(line, words)):
                return True
    if words and any(marker in low for marker in _SPAWN_MARKERS) and _mentions(line, words):
        return True
    return False


def _program_verifies(lines: list[str]) -> bool:
    for line in lines:
        low = line.lower()
        if any(marker in low for marker in _HASH_MARKERS) and any(marker in low for marker in _COMPARE_MARKERS):
            return True
    return False


def _program_hits(unit: TextFile | CodeBlock, comment: str) -> Iterator[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    if isinstance(unit, CodeBlock):
        numbered = [(unit.first_line + offset, text) for offset, text in enumerate(unit.lines)]
    else:
        numbered = list(enumerate(unit.lines, start=1))
    for number, text in numbered:
        stripped = text.strip()
        if stripped and not stripped.startswith(comment):
            rows.append((number, text))
    if _program_verifies([text for _number, text in rows]):
        return
    for position, (number, text) in enumerate(rows):
        if not any(_moving(url) for url in _urls(text)):
            continue
        window = rows[position:position + _PROGRAM_WINDOW + 1]
        if not any(any(marker in line.lower() for marker in _FETCH_MARKERS) for _n, line in window):
            continue
        words: set[str] | None = None
        written = False
        # The file may be opened a few lines before the URL is requested (a stream created first, then fed).
        for _n, line in rows[max(0, position - _PROGRAM_LEAD):position + _PROGRAM_WINDOW + 1]:
            targets = _write_targets(line)
            if targets is not None and not written:
                written = True
                words = targets
        if not written:
            continue
        if any(_execute_line(line, words or set()) for _n, line in window):
            yield number, text.strip()


# --- the rule ---------------------------------------------------------------------------------------------------------

def _kind(unit: TextFile | CodeBlock) -> str:
    if isinstance(unit, CodeBlock):
        language = unit.language
        if language in SHELL_LANGUAGES or language == "powershell":
            return "shell"
        if language == "python":
            return "python"
        return "js" if language in _JS_LANGUAGES else ""
    path = unit.path.lower()
    if path.endswith(_SHELL_EXTENSIONS):
        return "shell"
    if path.endswith(_PYTHON_EXTENSIONS):
        return "python"
    return "js" if path.endswith(_JS_EXTENSIONS) else ""


def _finding(path: str, line: int, matched: str) -> Finding:
    return Finding(RULE_ID, SEVERITY, TITLE, Location(path, line), excerpt(matched), fingerprint(RULE_ID, path, matched), MALICIOUS)


def detect(package: Package) -> Iterator[Finding]:
    # Imported here: rules/skill.py imports this module when the rule is registered, so a top-level import would cycle.
    from spellwarden_scan.rules.skill import logical_commands

    reported: set[tuple[str, int]] = set()
    for unit in package.scripts():
        kind = _kind(unit)
        if kind == "shell":
            hits = _shell_hits(list(_commands(unit, logical_commands)))
        elif kind == "python":
            hits = _program_hits(unit, "#")
        elif kind == "js":
            hits = _program_hits(unit, "//")
        else:
            continue
        for line, matched in hits:
            if (unit.path, line) in reported:
                continue
            reported.add((unit.path, line))
            yield _finding(unit.path, line, matched)
            if len(reported) >= _PER_PACKAGE:
                return
