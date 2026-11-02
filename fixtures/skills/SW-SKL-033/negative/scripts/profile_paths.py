"""Tell a person which paths of a report point at a browser profile."""
import re
import shutil

PROFILE_PATHS = re.compile(
    r"(Application Support/Google/Chrome|\.config/google-chrome|Google/Chrome/User Data|Microsoft/Edge/User Data|BraveSoftware)"
)


def mentions_profile(text: str) -> bool:
    return PROFILE_PATHS.search(text) is not None


def export(report_dir: str, out_dir: str) -> None:
    shutil.copytree(report_dir, out_dir, dirs_exist_ok=True)
