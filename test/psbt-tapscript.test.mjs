import { test } from "node:test";
import assert from "node:assert/strict";
import { hodlControlBlock, hodlDisasmTapscript, hodlLooksOrdEnvelope, hodlTapWitnessPath } from "../src/js/psbt-tapscript.js";

const NUMS = Uint8Array.from(Buffer.from("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0", "hex"));

test("control block splits version, parity, key, nodes", () => {
  const raw = new Uint8Array(33 + 64);
  raw[0] = 0xc1;
  raw.set(NUMS, 1);
  const parsed = hodlControlBlock(raw);
  assert.equal(parsed.leafVersion, 0xc0);
  assert.equal(parsed.parity, 1);
  assert.equal(parsed.nodes.length, 2);
});

test("key-path vs script-path vs annex", () => {
  assert.equal(hodlTapWitnessPath([new Uint8Array(64)]).path, "key");
  const script = Uint8Array.of(0x20, ...new Uint8Array(32), 0xac);
  const cb = new Uint8Array(33);
  cb[0] = 0xc0;
  cb.set(NUMS, 1);
  const path = hodlTapWitnessPath([new Uint8Array(64), script, cb, Uint8Array.of(0x50, 1)]);
  assert.equal(path.path, "script");
  assert.equal(path.annex[0], 0x50);
});

test("disasm and ord envelope", () => {
  assert.deepEqual(hodlDisasmTapscript(Uint8Array.of(0x20, ...new Uint8Array(32), 0xba, 0xac)), ["PUSH(32)", "OP_CHECKSIGADD", "OP_CHECKSIG"]);
  assert.equal(hodlLooksOrdEnvelope(Uint8Array.of(0x00, 0x63, 0x03, 0x6f, 0x72, 0x64)), true);
});
