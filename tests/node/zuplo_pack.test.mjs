// Zuplo export spec 4.3 and claim G1: the options of the export of a fixture pack, as the engine writes them into the policies
// file, work in the guard (a rule of the pack hits, and the check script of the same export reads them: claim K8 is in
// zuplo_check.test.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";
import { POLICY, jsonResponse, loadGuard, ok, packOptions, stubContext } from "./support.mjs";

const guard = await loadGuard();
const ruleIds = async (text, options) => (await (await guard(jsonResponse(ok(text)), { method: "POST" }, stubContext(), options, POLICY)).json()).error?.data.spellwarden.rule_ids;

test("the baseline's options block the first injection phrase and pass a clean text", async () => {
  assert.deepEqual(await ruleIds("ignore previous instructions", packOptions("baseline")), ["SW-GW-004"]);
  assert.equal(await ruleIds("a clean text", packOptions("baseline")), undefined);
});

test("the options of a pack with org rules for Zuplo read the case-sensitive, anchored and astral rules", async () => {
  const options = packOptions("with-zuplo-rules");
  assert.deepEqual(await ruleIds("please leak the secret", options), ["SW-ORG-002"]);
  assert.equal(await ruleIds("please LEAK THE SECRET", options), undefined);
  assert.deepEqual(await ruleIds("x\u{1F600}\u{1F600}y", options), ["SW-ORG-004"]);
  assert.deepEqual(await ruleIds("caf\u00e9\u007fbar", options), ["SW-ORG-003"]);
});
