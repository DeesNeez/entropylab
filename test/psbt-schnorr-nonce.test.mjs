import { test } from "node:test";
import assert from "node:assert/strict";
import { hodlParseSchnorr, hodlTapSighashProblems, hodlCompareSchnorrNonces, hodlTapKeySigs } from "../src/js/psbt-schnorr.js";

const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const rA = new Uint8Array(32).fill(0x11);
const key = new Uint8Array(32).fill(0x33);

test("parses 64 and 65 byte Schnorr signatures", () => {
  const raw = new Uint8Array(64);
  raw.set(rA);
  assert.equal(hodlParseSchnorr(raw).sighash, 0);
  const raw2 = new Uint8Array(65);
  raw2.set(rA);
  raw2[64] = 0x81;
  assert.equal(hodlParseSchnorr(raw2).sighash, 0x81);
});

test("DEFAULT and ALL are safe; ANYONECANPAY is not", () => {
  const label = (p) => "0x" + p.toString(16);
  assert.deepEqual(hodlTapSighashProblems(0, 1, label), []);
  assert.ok(hodlTapSighashProblems(0x82, 0x82, label).length >= 2);
});

test("same R on two inputs is flagged", () => {
  const scan = hodlCompareSchnorrNonces([
    { input: 0, r: rA, pubkey: key },
    { input: 1, r: rA, pubkey: key },
  ], eq);
  assert.equal(scan.possible.length, 1);
});

test("tap key sig records are collected", () => {
  const raw = new Uint8Array(64);
  raw.set(rA);
  const keys = hodlTapKeySigs([{ type: 19, keydata: new Uint8Array(), val: raw }], (e, t) => e.filter((x) => x.type === t));
  assert.equal(keys.length, 1);
});
