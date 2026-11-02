import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

// A folder of the tool's own: nothing is copied into it.
const profile = join(homedir(), ".config", "tab-helper", "browser-profile");
spawn("chrome", ["--remote-debugging-port=9222", `--user-data-dir=${profile}`, "about:blank"]);
