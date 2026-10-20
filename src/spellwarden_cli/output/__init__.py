"""The output formats (spec 6.9): each a pure function of a `Report`."""
from __future__ import annotations

from spellwarden_cli.output import codequality, json_out, markdown, sarif, text

FORMATS = {
    "text": text.render,
    "json": json_out.render,
    "sarif": sarif.render,
    "markdown": markdown.render,
    "gitlab-codequality": codequality.render,
}
