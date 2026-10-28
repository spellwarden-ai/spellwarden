// Zuplo export spec claims K1 to K8: the check script, run by Node against the projects `tests/zuplo_ci.py write` made.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { DIR } from "./support.mjs";

const SCRIPT = join(DIR, "guard", "spellwarden-zuplo-check.mjs");
const PROJECTS = join(DIR, "projects");

function check(project) {
  const done = spawnSync(process.execPath, [SCRIPT, join(PROJECTS, project)], { encoding: "utf8" });
  return { exit: done.status, lines: done.stdout.split("\n").filter((line) => line !== ""), stderr: done.stderr };
}

describe("the projects", () => {
  for (const project of readdirSync(PROJECTS).sort()) {
    test(project, () => {
      const expect = JSON.parse(readFileSync(join(PROJECTS, project, "expect.json"), "utf8"));
      const got = check(project);
      assert.equal(got.stderr, "");
      assert.equal(got.exit, expect.exit);
      if (expect.prefix !== undefined) {
        assert.equal(got.lines.length, 1);
        assert.ok(got.lines[0].startsWith(expect.prefix), got.lines[0]);
      } else {
        assert.deepEqual(got.lines, expect.lines);
      }
    });
  }
});

describe("the claims", () => {
  test("K1 a wired project exits 0 with the summary line", () => {
    const got = check("wired");
    assert.equal(got.exit, 0);
    assert.deepEqual(got.lines, ['spellwarden-zuplo-check: 2 MCP routes, 0 failures, pack "Spellwarden Baseline for Agents" 1.0']);
  });

  test("K5 a project that cannot be read exits 2 and says which file", () => {
    const got = spawnSync(process.execPath, [SCRIPT, join(PROJECTS, "does-not-exist")], { encoding: "utf8" });
    assert.equal(got.status, 2);
    assert.match(got.stdout, /^spellwarden-zuplo-check: config\/policies\.json: ENOENT/);
  });

  test("K7 a pack name with quotes and newlines is one JSON string on the summary line", () => {
    const got = check("pack-names-quotes");
    assert.equal(got.exit, 0);
    assert.equal(got.lines.length, 1);
    const name = JSON.parse(got.lines[0].match(/pack ("(?:[^"\\]|\\.)*") /)[1]);
    assert.match(name, /["\n\\]/);
  });

  test("K8 the canonical options hash of the script equals Python's for every fixture pack", () => {
    const packs = readdirSync(PROJECTS).filter((name) => name.startsWith("pack-"));
    assert.ok(packs.length >= 6);
    for (const project of packs) assert.equal(check(project).exit, 0, project);
  });
});
