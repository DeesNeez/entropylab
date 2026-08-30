import { test } from "node:test";
import assert from "node:assert/strict";
import { hodlPsbtVersion, hodlTxFromPsbtV2 } from "../src/js/psbt-v2.js";

const u32 = (n) => Uint8Array.of(n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255);
const r32 = (b) => new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true);
const r64 = (b) => {
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(b[i]) << BigInt(8 * i);
  return v;
};
const find = (entries, type) => entries.filter((e) => e.type === type);
const varint = (b) => [b[0], 1];

test("missing version field is v0", () => {
  assert.equal(hodlPsbtVersion([], r32), 0);
  assert.equal(hodlPsbtVersion([{ type: 251, keydata: new Uint8Array(), val: u32(2) }], r32), 2);
});

test("v2 tx is built from input 0x0e/0x0f and output 0x03/0x04", () => {
  const txid = new Uint8Array(32).fill(9);
  const amount = Uint8Array.of(0xe8, 0x03, 0, 0, 0, 0, 0, 0);
  const script = Uint8Array.of(0x00, 0x14, ...new Uint8Array(20));
  const tx = hodlTxFromPsbtV2(
    [{ type: 2, keydata: new Uint8Array(), val: u32(2) }],
    [[{ type: 14, keydata: new Uint8Array(), val: txid }, { type: 15, keydata: new Uint8Array(), val: u32(1) }]],
    [[{ type: 3, keydata: new Uint8Array(), val: amount }, { type: 4, keydata: new Uint8Array(), val: script }]],
    { hodlFind: find, hodlR32: r32, hodlR64: r64, hodlVarInt: varint },
  );
  assert.equal(tx.version, 2);
  assert.equal(tx.inputs[0].vout, 1);
  assert.equal(tx.outputs[0].amount, 1000n);
});
