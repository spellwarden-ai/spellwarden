// Shared by the Node tests of the Zuplo guard and the check script: where `tests/zuplo_ci.py write` put the files, the
// vectors, and stubs for the parts of Zuplo's runtime the guard touches.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export const ROOT = new URL("../../", import.meta.url).pathname;
export const DIR = process.env.SPELLWARDEN_ZUPLO_DIR;
if (!DIR) throw new Error("SPELLWARDEN_ZUPLO_DIR is not set: run `make check-node`, or `uv run --locked python tests/zuplo_ci.py write DIR` and set it");
export const DATA = JSON.parse(readFileSync(join(ROOT, "fixtures", "zuplo_vectors.json"), "utf8"));
export const baselineOptions = () => ({ spellwarden: { format: 1 }, maxBodyBytes: 1048576, onTooLarge: "block", checks: DATA.check_sets.baseline, deployChecks: {} });
export const packOptions = (name) => JSON.parse(readFileSync(join(DIR, "packs", name, "spellwarden-policies.json"), "utf8")).policies[0].handler.options;

export async function loadGuard() {
  return (await import(pathToFileURL(join(DIR, "guard", "spellwarden-mcp-guard.ts")).href)).default;
}

// A stub of ZuploContext: it records the log calls and the hooks.
export function stubContext() {
  const logs = [];
  const hooks = [];
  return {
    logs,
    hooks,
    requestId: "request-1",
    log: { warn: (...args) => logs.push(["warn", ...args]), error: (...args) => logs.push(["error", ...args]) },
    addResponseSendingHook: (hook) => hooks.push(hook),
  };
}

export const encode = (text) => new TextEncoder().encode(text);

// The bytes of a vector: `body_expand` (prefix, repeat times, suffix), `body_b64` or `body`.
export function bodyBytes(vector) {
  if (vector.body_expand) {
    const { prefix = "", repeat, times, suffix = "" } = vector.body_expand;
    return encode(prefix + repeat.repeat(times) + suffix);
  }
  if (vector.body_b64) return new Uint8Array(Buffer.from(vector.body_b64, "base64"));
  return encode(vector.body ?? "");
}

// A body delivered in chunks of `size` bytes; `spy.cancelled` says whether the reader cancelled it.
export function streamOf(bytes, size, spy = {}) {
  let at = 0;
  return new ReadableStream({
    pull(controller) {
      if (at >= bytes.length) {
        controller.close();
        return;
      }
      controller.enqueue(bytes.slice(at, at + size));
      at += size;
    },
    cancel() {
      spy.cancelled = true;
    },
  });
}

export function responseOf(vector, spy = {}) {
  const headers = new Headers();
  const media = vector.media ?? "application/json";
  if (media !== "") headers.set("content-type", media);
  if (vector.encoding) headers.set("content-encoding", vector.encoding);
  if (vector.content_length !== undefined) headers.set("content-length", String(vector.content_length));
  const bytes = bodyBytes(vector);
  const body = vector.no_body ? null : streamOf(bytes, vector.chunk_size ?? Math.max(bytes.length, 1), spy);
  return new Response(body, { status: vector.status ?? 200, headers });
}

export function optionsOf(vector) {
  if ("raw_options" in vector) return vector.raw_options;
  const options = { spellwarden: { format: 1 }, maxBodyBytes: 1048576, onTooLarge: "block", checks: DATA.check_sets[vector.checks], deployChecks: {},
    ...(vector.options ?? {}) };
  for (const key of vector.drop ?? []) delete options[key];
  return options;
}

export const POLICY = "spellwarden-mcp-guard";
export const ok = (text = "fine") => JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text }] } });
export const jsonResponse = (text, headers = {}, status = 200) =>
  new Response(text, { status, headers: { "content-type": "application/json", ...headers } });
