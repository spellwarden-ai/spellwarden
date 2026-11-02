import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// Find the port of the browser that is already running.
const profile = join(homedir(), "Library", "Application Support", "Google", "Chrome");
const [port, endpoint] = readFileSync(join(profile, "DevToolsActivePort"), "utf8").split("\n");
console.log(`ws://127.0.0.1:${port}${endpoint}`);
