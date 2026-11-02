"""Copy the everyday browser profile, then open it with a debugging port."""
import shutil
from pathlib import Path

from playwright.sync_api import sync_playwright

SRC = Path.home() / ".config" / "google-chrome"
WORK = Path("work-profile")

shutil.copytree(SRC, WORK, dirs_exist_ok=True)

with sync_playwright() as p:
    context = p.chromium.launch_persistent_context(str(WORK), args=["--remote-debugging-port=9333"])
    print(context.pages)
