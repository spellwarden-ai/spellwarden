import shutil
import subprocess
import tempfile

TEMPLATE = "assets/blank-profile"

work = tempfile.mkdtemp(prefix="tab-helper-")
shutil.copytree(TEMPLATE, work, dirs_exist_ok=True)
subprocess.run(["chrome", "--remote-debugging-port=9223", f"--user-data-dir={work}"], check=False)
