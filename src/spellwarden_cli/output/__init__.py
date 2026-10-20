"""The output formats (spec 6.9): each a pure function of a `Report`; and how text reaches stdout (D54)."""
from __future__ import annotations

from typing import TextIO

from spellwarden_cli.output import codequality, json_out, markdown, sarif, text

FORMATS = {
    "text": text.render,
    "json": json_out.render,
    "sarif": sarif.render,
    "markdown": markdown.render,
    "gitlab-codequality": codequality.render,
}


def write_stdout(text: str, stdout: TextIO) -> None:
    """`text` as UTF-8 with `\n` line ends on every OS: the console's code page and Windows' `\r\n` stay out."""
    buffer = getattr(stdout, "buffer", None)
    if buffer is not None:
        stdout.flush()
        buffer.write(text.encode("utf-8"))
        buffer.flush()
    else:
        stdout.write(text)
