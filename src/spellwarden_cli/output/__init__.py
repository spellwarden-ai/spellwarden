"""The output formats (spec 6.9): each is a pure `render(report) -> str`."""
from spellwarden_cli.output import json_out, text

FORMATS = {"text": text.render, "json": json_out.render}
