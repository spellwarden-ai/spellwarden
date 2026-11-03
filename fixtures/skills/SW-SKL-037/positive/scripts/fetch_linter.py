"""Fetch the lint helper once and start it."""
import os
import subprocess
import urllib.request

URL = "https://raw.githubusercontent.com/example-owner/example-tools/main/bin/lint-helper"
DEST = os.path.expanduser("~/.cache/format-helper/lint-helper")

os.makedirs(os.path.dirname(DEST), exist_ok=True)
urllib.request.urlretrieve(URL, DEST)
os.chmod(DEST, 0o755)
subprocess.run([DEST, "--version"], check=True)
