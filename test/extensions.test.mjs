// Unit tests for the extension manifest format and registry logic.
// Run with `npm run test:extensions` or `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import "../src/js/extensions.js";

const { EntropyLab } = globalThis;

test("validateManifest normalizes a good manifest and freezes the result", () => {
  const normalized = EntropyLab.validateManifest({
    id: "echo-demo",
    name: "  Echo demo ",
    version: "1.0.0",
    author: "someone",
    description: "Echoes text.",
    activate() {},
  });
  assert.equal(normalized.name, "Echo demo");
  assert.equal(normalized.author, "someone");
  assert.equal(normalized.description, "Echoes text.");
  assert.ok(Object.isFrozen(normalized));
  assert.equal(typeof normalized.activate, "function");
});

test("validateManifest rejects malformed manifests with clear errors", () => {
  const cases = [
    [null, /manifest must be an object/],
    [{}, /Extension id/],
    [{ id: "bad id!", name: "x", version: "1.0.0" }, /Extension id/],
    [{ id: "ok", name: "", version: "1.0.0" }, /Extension name/],
    [{ id: "ok", name: "x", version: "1.0" }, /Extension version/],
    [{ id: "ok", name: "x", version: "1.0.0", description: "x".repeat(601) }, /Extension description/],
    [{ id: "ok", name: "x", version: "1.0.0", activate: 123 }, /Extension activate/],
  ];
  for (const [bad, pattern] of cases) {
    assert.throws(() => EntropyLab.validateManifest(bad), pattern);
  }
});

test("registerExtension stores a frozen public record and activate runs", () => {
  let activated = 0;
  const record = EntropyLab.registerExtension({
    id: "registry-demo",
    name: "Registry demo",
    version: "0.1.0",
    activate() {
      activated += 1;
    },
  });
  assert.equal(activated, 1);
  assert.equal(record.status, "active");
  assert.ok(Object.isFrozen(record));
  const listed = EntropyLab.listExtensions().find((entry) => entry.id === "registry-demo");
  assert.ok(listed);
  EntropyLab.unregisterExtension("registry-demo");
  // Re-registering the same id after unregister must succeed.
  EntropyLab.registerExtension({ id: "registry-demo", name: "x", version: "1.0.0" });
  EntropyLab.unregisterExtension("registry-demo");
});

test("registerExtension rejects duplicate ids", () => {
  const manifest = { id: "dupe", name: "Dupe", version: "1.0.0" };
  EntropyLab.registerExtension(manifest);
  assert.throws(() => EntropyLab.registerExtension(manifest), /already loaded/);
  EntropyLab.unregisterExtension("dupe");
});

test("unregisterExtension removes the record", () => {
  EntropyLab.registerExtension({ id: "gone", name: "Gone", version: "1.0.0" });
  assert.equal(EntropyLab.unregisterExtension("gone"), true);
  assert.throws(() => EntropyLab.unregisterExtension("gone"), /No extension/);
});

test("loadSource registers and records the source's SHA-256 digest", async () => {
  const source = `EntropyLab.registerExtension({
    id: "digest-demo",
    name: "Digest demo",
    version: "1.0.0",
    activate(api) {
      api.addPanel({ title: "P", render: () => "<p>ok</p>" });
    },
  })`;
  await EntropyLab.loadSource(source);
  const record = EntropyLab.listExtensions().find((entry) => entry.id === "digest-demo");
  assert.ok(record);
  assert.equal(record.status, "active");
  assert.match(record.digest, /^[0-9a-f]{64}$/);
  EntropyLab.unregisterExtension("digest-demo");
});

test("loadSource marks a failing activate with the thrown message", async () => {
  await EntropyLab.loadSource(`EntropyLab.registerExtension({
    id: "boom",
    name: "Boom",
    version: "1.0.0",
    activate() { throw new Error("kaput"); },
  })`);
  const record = EntropyLab.listExtensions().find((entry) => entry.id === "boom");
  assert.equal(record.status, "failed");
  assert.equal(record.error, "kaput");
  EntropyLab.unregisterExtension("boom");
});

test("loadSource rejects empty source", async () => {
  await assert.rejects(EntropyLab.loadSource("   "), /Extension source is empty/);
});
