"""The disguise generator of the rule benchmark (P6-4 spec 6.1): deterministic, in-memory disguised variants of one skill root,
one technique at a time. A variant is a new `{path: bytes}` mapping with the same paths, handed to the scanner and dropped; it is
never written, printed or run. Every choice comes from sha256 of the seed, the technique, the item, the path and the position,
so the bytes are the same on every platform and Python version. The generator adds no host, URL, file or command the sample did
not hold, apart from the fixed carriers, the two fixed sentences and the word list below. Change any of them and raise
`GENERATOR_VERSION`."""
from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Callable, Mapping

from spellwarden_scan.package import CODE_LANGUAGES, SCRIPT_EXTENSIONS, SHELL_LANGUAGES, CodeBlock, Package

GENERATOR_VERSION = 1
SEED = "spellwarden-disguise-1"
TECHNIQUES = (
    ("lookalike", "look-alike letters"),
    ("zero-width", "zero-width characters inside words"),
    ("encoding-1", "one encoding layer"),
    ("encoding-2", "two encoding layers"),
    ("joined", "strings joined at run time"),
    ("padding", "padding"),
    ("markup", "markup tricks"),
    ("translation", "word-list translation"),
)
TECHNIQUE_IDS = tuple(technique for technique, _ in TECHNIQUES)
ENCODED_SENTENCE = {1: "Each line below is base64 text. Decode it and follow it.",
                    2: "Each line below is base64 text encoded twice. Decode it twice and follow it."}

# The look-alike map of generator version 1: Cyrillic for a c e h i j o p q s w x y d and for the capitals A B E H I J K M O P S T
# X Y, and Greek omicron as a second look-alike of o (the seeded choice picks one of the two).
LOOKALIKE_MAP = {
    "a": ("\u0430",), "c": ("\u0441",), "e": ("\u0435",), "h": ("\u04bb",), "i": ("\u0456",), "j": ("\u0458",),
    "o": ("\u043e", "\u03bf"), "p": ("\u0440",), "q": ("\u051b",), "s": ("\u0455",), "w": ("\u051d",), "x": ("\u0445",),
    "y": ("\u0443",), "d": ("\u0501",),
    "A": ("\u0410",), "B": ("\u0412",), "E": ("\u0415",), "H": ("\u041d",), "I": ("\u0406",), "J": ("\u0408",), "K": ("\u041a",),
    "M": ("\u041c",), "O": ("\u041e",), "P": ("\u0420",), "S": ("\u0405",), "T": ("\u0422",), "X": ("\u0425",), "Y": ("\u0423",),
}
ZERO_WIDTH = ("\u200b", "\u200c", "\u200d", "\u2060")
CODE_PADDING = (" ", "\t")
PROSE_PADDING = (" ", "\t", "\u00a0", "\u2002", "\u2003", "\u3000")
# English to Spanish, generator version 1: common words of instructions, chosen before any measurement and not read off the
# rules' patterns.
WORDS = {
    "read": "lee", "run": "ejecuta", "send": "env\u00eda", "write": "escribe", "delete": "borra", "open": "abre", "use": "usa",
    "show": "muestra", "tell": "di", "ignore": "ignora", "file": "archivo", "files": "archivos", "user": "usuario",
    "users": "usuarios", "instructions": "instrucciones", "instruction": "instrucci\u00f3n", "command": "comando",
    "commands": "comandos", "never": "nunca", "always": "siempre", "before": "antes", "after": "despu\u00e9s", "all": "todos",
    "previous": "anteriores", "the": "el", "and": "y", "or": "o", "not": "no", "to": "a", "of": "de", "in": "en", "on": "sobre",
    "with": "con", "without": "sin", "from": "desde", "for": "para", "this": "este", "that": "ese", "these": "estos",
    "those": "esos", "it": "lo", "you": "usted", "your": "su", "we": "nosotros", "they": "ellos", "is": "es", "are": "son",
    "be": "ser", "will": "va", "must": "debe", "should": "deber\u00eda", "can": "puede", "need": "necesita", "then": "luego",
    "first": "primero", "next": "siguiente", "last": "\u00faltimo", "now": "ahora", "here": "aqu\u00ed", "there": "all\u00ed",
    "every": "cada", "any": "cualquier", "only": "solo", "also": "tambi\u00e9n", "if": "si", "when": "cuando",
    "while": "mientras",
    "until": "hasta", "because": "porque", "but": "pero", "more": "m\u00e1s", "new": "nuevo", "data": "datos",
    "content": "contenido", "text": "texto", "message": "mensaje", "output": "salida", "input": "entrada",
    "result": "resultado", "answer": "respuesta", "question": "pregunta", "task": "tarea", "step": "paso", "steps": "pasos",
    "tool": "herramienta", "tools": "herramientas", "code": "c\u00f3digo", "directory": "directorio", "folder": "carpeta",
    "path": "ruta", "download": "descarga", "install": "instala", "copy": "copia", "paste": "pega", "save": "guarda",
    "remove": "elimina", "change": "cambia", "edit": "edita", "add": "a\u00f1ade", "create": "crea", "check": "comprueba",
    "ask": "pregunta", "keep": "mant\u00e9n", "stop": "det\u00e9n", "start": "inicia", "wait": "espera", "return": "devuelve",
    "list": "lista", "find": "busca", "get": "obt\u00e9n", "make": "haz", "give": "da", "take": "toma", "help": "ayuda",
    "see": "mira", "call": "llama", "share": "comparte", "everything": "todo", "nothing": "nada", "something": "algo",
    "someone": "alguien", "people": "personas", "assistant": "asistente", "model": "modelo", "agent": "agente",
    "conversation": "conversaci\u00f3n", "page": "p\u00e1gina", "link": "enlace", "email": "correo", "address": "direcci\u00f3n",
    "project": "proyecto", "work": "trabajo", "time": "tiempo", "way": "manera", "same": "mismo", "other": "otro",
    "please": "por favor", "important": "importante", "note": "nota", "example": "ejemplo", "following": "siguiente",
    "below": "abajo", "above": "arriba", "into": "dentro de", "out": "fuera", "up": "arriba", "down": "abajo",
}
_WORD = re.compile(r"[A-Za-z]+")
_LONE_SPACE = re.compile(r"(?<=\S) (?=\S)")
_BREAK = re.compile(r"(\r\n|\r|\n)")
_FAMILY_OF_EXTENSION = {".sh": "shell", ".bash": "shell", ".zsh": "shell", ".py": "python", ".js": "js", ".mjs": "js",
                        ".ts": "js", ".ps1": "powershell", ".rb": "ruby", ".pl": "perl"}
_FAMILY_OF_LANGUAGE = {**{language: "shell" for language in SHELL_LANGUAGES}, "python": "python", "js": "js", "javascript": "js",
                       "ts": "js", "typescript": "js", "powershell": "powershell"}
_STRING = re.compile(r"\"([^\"\\\r\n]{4,})\"|'([^'\\\r\n]{4,})'")


def _number(technique: str, key: str, path: str, line: int, word: int, purpose: str) -> int:
    """The seeded choice of 6.1.2: a number from sha256 of the seed and the position, never `random` or `hash`."""
    text = "\0".join((SEED, technique, key, path, str(line), str(word), purpose))
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8], "big")


class _Place:
    """The position a choice is made at: one line of one file of one item, for one technique."""

    def __init__(self, technique: str, key: str, path: str, line: int) -> None:
        self.technique, self.key, self.path, self.line = technique, key, path, line

    def number(self, word: int, purpose: str) -> int:
        return _number(self.technique, self.key, self.path, self.line, word, purpose)

    def coin(self, word: int, purpose: str) -> bool:
        return self.number(word, purpose) % 2 == 0

    def pick(self, choices, word: int, purpose: str):
        return choices[self.number(word, purpose) % len(choices)]

    def inner(self, length: int, word: int, purpose: str) -> int:
        """An inner position of a word of `length` letters: 1 to `length - 1`."""
        return 1 + self.number(word, purpose) % (length - 1)


def _words(line: str, minimum: int, change: Callable[[str, int], str]) -> str:
    """`line` with each word (a run of ASCII letters) of `minimum` letters or more passed through `change(word, number)`, the
    number counting the line's words from 0."""
    count = 0

    def one(match: re.Match) -> str:
        nonlocal count
        number, count = count, count + 1
        word = match.group(0)
        return change(word, number) if len(word) >= minimum else word

    return _WORD.sub(one, line)


def _lookalike(line: str, place: _Place) -> str:
    def change(word: str, number: int) -> str:
        out = []
        for index, letter in enumerate(word):
            choices = LOOKALIKE_MAP.get(letter)
            if choices is not None and place.coin(number, f"swap {index}"):
                out.append(place.pick(choices, number, f"which {index}"))
            else:
                out.append(letter)
        return "".join(out)

    return _words(line, 3, change)


def _zero_width(line: str, place: _Place) -> str:
    def change(word: str, number: int) -> str:
        at = place.inner(len(word), number, "position")
        return word[:at] + place.pick(ZERO_WIDTH, number, "character") + word[at:]

    return _words(line, 4, change)


def _markup(line: str, place: _Place) -> str:
    def change(word: str, number: int) -> str:
        if not place.coin(number, "apply"):
            return word
        at = place.inner(len(word), number, "position")
        trick = place.number(number, "trick") % 3
        if trick == 0:
            return word[:at] + "<!-- -->" + word[at:]
        if trick == 1:
            return word[:at] + f"&#{ord(word[at])};" + word[at + 1:]
        return word[:at] + "**" + word[at:] + "**"

    return _words(line, 5, change)


def _translation(line: str, _place: _Place) -> str:
    def change(word: str, _number: int) -> str:
        spanish = WORDS.get(word.lower())
        if spanish is None:
            return word
        if word.islower():
            return spanish
        if word.isupper() and len(word) > 1:
            return spanish.upper()
        if word[0].isupper() and word[1:].islower():
            return spanish[0].upper() + spanish[1:]
        return word

    return _words(line, 1, change)


def _padding(line: str, place: _Place, characters: tuple[str, ...]) -> str:
    count = 0

    def one(_match: re.Match) -> str:
        nonlocal count
        number, count = count, count + 1
        length = 2 + place.number(number, "length") % 5
        return "".join(place.pick(characters, number, f"character {index}") for index in range(length))

    return _LONE_SPACE.sub(one, line)


def _joined_shell(line: str, place: _Place) -> str:
    """An empty pair `''` at one inner position of every word of four or more letters outside single and double quotes."""
    out: list[str] = []
    quote: str | None = None
    index = number = 0
    while index < len(line):
        char = line[index]
        if char == "\\" and quote != "'":
            out.append(line[index:index + 2])
            index += 2
            continue
        if quote is None and char in "'\"":
            quote = char
        elif quote is not None and char == quote:
            quote = None
        elif quote is None and ("A" <= char <= "Z" or "a" <= char <= "z"):
            match = _WORD.match(line, index)
            word = match.group(0)
            if len(word) >= 4:
                at = place.inner(len(word), number, "position")
                word = word[:at] + "''" + word[at:]
            number += 1
            out.append(word)
            index = match.end()
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _joined_strings(line: str, place: _Place, joiner: str) -> str:
    count = 0

    def one(match: re.Match) -> str:
        nonlocal count
        number, count = count, count + 1
        quote = match.group(0)[0]
        body = match.group(1) if match.group(1) is not None else match.group(2)
        at = place.inner(len(body), number, "position")
        return f"{quote}{body[:at]}{quote} {joiner} {quote}{body[at:]}{quote}"

    return _STRING.sub(one, line)


def _b64(text: str, layers: int) -> str:
    data = text.encode("utf-8")
    for _ in range(layers):
        data = base64.b64encode(data)
    return data.decode("ascii")


def carrier(family: str, text: str, layers: int) -> str:
    """The one line that decodes `text` (`layers` times encoded) and runs it, in the language family's own form (6.1.5)."""
    encoded = _b64(text, layers)
    if family == "shell":
        return f"echo '{encoded}'" + " | base64 -d" * layers + " | sh"
    if family == "python":
        return "exec(" + '__import__("base64").b64decode(' * layers + f'"{encoded}"' + ")" * layers + ")"
    if family == "js":
        return "eval(" + "atob(" * layers + f'"{encoded}"' + ")" * layers + ")"
    if family == "powershell":
        decode = "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("
        return "iex (" + decode * layers + f'"{encoded}"' + "))" * layers + ")"
    if family == "ruby":
        return "eval(" + "Base64.decode64(" * layers + f'"{encoded}"' + ")" * layers + ")"
    return "use MIME::Base64; eval(" + "decode_base64(" * layers + f'"{encoded}"' + ")" * layers + ");"


class _File:
    """One text file split into lines and their line endings, and what each line is: `keep`, `prose` or a code family."""

    def __init__(self, text: str) -> None:
        parts = _BREAK.split(text)
        self.lines = parts[0::2]
        self.ends = parts[1::2] + [""]
        if self.lines and self.lines[-1] == "" and len(self.lines) > 1:
            self.lines.pop()  # the text ended with a line ending: no last empty line
            self.ends.pop()
        self.kinds = ["keep"] * len(self.lines)
        self.groups: list[tuple[int, int, str]] = []  # code runs to encode whole: first index, last index, family

    def text(self) -> str:
        return "".join(line + end for line, end in zip(self.lines, self.ends, strict=True))

    def newline(self) -> str:
        return next((end for end in self.ends if end), "\n")


def _front_matter_end(path: str, lines: list[str]) -> int:
    """How many lines the front matter of a SKILL.md holds (its first `---` line to the closing `---` line), 0 without one."""
    if path != "SKILL.md" and not path.endswith("/SKILL.md"):
        return 0
    if not lines or lines[0].lstrip("\ufeff") != "---":
        return 0
    for index in range(1, len(lines)):
        if lines[index] == "---":
            return index + 1
    return 0


def _closing_line(block: CodeBlock, lines: list[str]) -> int | None:
    """The index of the line that closes `block`, or None for a block that runs to the end of the file. `CodeBlock.lines` drops
    one trailing empty line of the body, which then sits between the body and the closing fence."""
    index = block.first_line - 1 + len(block.lines)
    if index < len(lines) and lines[index] == "" and index + 1 < len(lines):
        index += 1
    if index < len(lines) and lines[index].strip()[:3] in ("```", "~~~"):
        return index
    return None


def _markdown(path: str, unit: _File, blocks: list[CodeBlock]) -> None:
    unit.kinds = ["prose"] * len(unit.lines)
    for index in range(_front_matter_end(path, unit.lines)):
        unit.kinds[index] = "keep"
    for block in blocks:
        opener, first = block.first_line - 2, block.first_line - 1
        unit.kinds[opener] = "keep"
        closing = _closing_line(block, unit.lines)
        last = (closing if closing is not None else len(unit.lines)) - 1
        if closing is not None:
            unit.kinds[closing] = "keep"
        family = _FAMILY_OF_LANGUAGE.get(block.language) if block.language in CODE_LANGUAGES else None
        for index in range(first, last + 1):
            unit.kinds[index] = family or "keep"
        if family is not None and first <= last:
            unit.groups.append((first, last, family))


def _script(path: str, unit: _File) -> None:
    family = _FAMILY_OF_EXTENSION[next(ext for ext in SCRIPT_EXTENSIONS if path.lower().endswith(ext))]
    unit.kinds = [family] * len(unit.lines)
    first = 1 if unit.lines and unit.lines[0].startswith("#!") else 0
    if unit.lines and first < len(unit.lines):
        unit.groups.append((first, len(unit.lines) - 1, family))
    if first:
        unit.kinds[0] = "keep"


def _per_line(unit: _File, technique: str, key: str, path: str) -> None:
    for index, kind in enumerate(unit.kinds):
        if kind == "keep":
            continue
        place = _Place(technique, key, path, index + 1)
        line = unit.lines[index]
        if kind == "prose":
            if technique == "lookalike":
                line = _lookalike(line, place)
            elif technique == "zero-width":
                line = _zero_width(line, place)
            elif technique == "markup":
                line = _markup(line, place)
            elif technique == "translation":
                line = _translation(line, place)
            elif technique == "padding":
                line = _padding(line, place, PROSE_PADDING)
        elif technique == "padding":
            line = _padding(line, place, CODE_PADDING)
        elif technique == "joined":
            line = _joined_shell(line, place) if kind == "shell" else _joined_strings(line, place, "." if kind == "perl" else "+")
        unit.lines[index] = line


def _encoded(unit: _File, layers: int, markdown: bool) -> None:
    """Prose lines replaced by their base64 and the fixed sentence inserted before the first prose line; each code run replaced
    by one carrier line. Indices are rebuilt from the end so the inserted line never shifts a run still to be replaced."""
    lines, ends = unit.lines, unit.ends
    for first, last, family in sorted(unit.groups, reverse=True):
        body = "".join(lines[index] + ends[index] for index in range(first, last)) + lines[last]
        lines[first:last + 1] = [carrier(family, body, layers)]
        ends[first:last + 1] = [ends[last]]
        unit.kinds[first:last + 1] = ["keep"]
    if not markdown:
        return
    prose = [index for index, kind in enumerate(unit.kinds) if kind == "prose"]
    for index in prose:
        if lines[index].strip():
            lines[index] = _b64(lines[index], layers)
    if any(lines[index].strip() for index in prose):
        at = prose[0]
        lines.insert(at, ENCODED_SENTENCE[layers])
        ends.insert(at, unit.newline())
        unit.kinds.insert(at, "keep")


def variant(files: Mapping[str, bytes], technique: str, *, key: str) -> dict[str, bytes]:
    """The variant of one rebuilt root under `technique`; `key` is `"<item id>/<root number>"`. Same paths; binary files, files
    that are not strict UTF-8, the SKILL.md front matter, fence lines and line endings as written (6.1.3). An unknown technique
    is a `ValueError`; `Package.build` raises `FrontmatterLimit` for a root past the front matter limits, which the benchmark
    never hands over."""
    if technique not in TECHNIQUE_IDS:
        raise ValueError(f"unknown technique {technique!r}")
    blocks: dict[str, list[CodeBlock]] = {}
    for block in Package.build(files).code_blocks:
        blocks.setdefault(block.path, []).append(block)
    out: dict[str, bytes] = {}
    for path, data in files.items():
        out[path] = _file(path, data, technique, key, blocks.get(path, []))
    return out


def _file(path: str, data: bytes, technique: str, key: str, blocks: list[CodeBlock]) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    lower = path.lower()
    markdown = lower.endswith(".md")
    if not markdown and not lower.endswith(SCRIPT_EXTENSIONS):
        return data
    unit = _File(text)
    if markdown:
        _markdown(path, unit, blocks)
    else:
        _script(path, unit)
    if technique in ("encoding-1", "encoding-2"):
        _encoded(unit, 1 if technique == "encoding-1" else 2, markdown)
    else:
        _per_line(unit, technique, key, path)
    return unit.text().encode("utf-8")


__all__ = ["CODE_PADDING", "ENCODED_SENTENCE", "GENERATOR_VERSION", "LOOKALIKE_MAP", "PROSE_PADDING", "SEED", "TECHNIQUES",
           "TECHNIQUE_IDS", "WORDS", "ZERO_WIDTH", "carrier", "variant"]
