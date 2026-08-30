import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { hodlParseBitboxTranscript, hodlBitboxS2cTweak } from "../src/js/psbt-bitbox.js";

const hexDecode = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
const hexEncode = (bytes) => Buffer.from(bytes).toString("hex");
const sha256 = (bytes) => Uint8Array.from(createHash("sha256").update(Buffer.from(bytes)).digest());

const HOST = "11".repeat(32);
const OPENING = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
const COMMITMENT = hexEncode(sha256(hexDecode(HOST)));

test("empty transcript is inspect-only", () => {
  assert.equal(hodlParseBitboxTranscript("", hexDecode, sha256), null);
  assert.equal(hodlParseBitboxTranscript("   ", hexDecode, sha256), null);
});

test("one 32-byte field is the revealed host nonce, not the SHA256 commitment", () => {
  const parsed = hodlParseBitboxTranscript(`${HOST} ${OPENING}`, hexDecode, sha256);
  assert.equal(hexEncode(parsed.hostNonce), HOST);
  assert.equal(hexEncode(parsed.opening), OPENING);
  assert.equal(hexEncode(parsed.commitment), COMMITMENT);
  assert.equal(parsed.commitmentMatches, true);
});

test("SHA256(host_nonce) plus nonce plus opening is accepted in either 32-byte order", () => {
  const a = hodlParseBitboxTranscript(`${COMMITMENT}\n${OPENING}\n${HOST}`, hexDecode, sha256);
  const b = hodlParseBitboxTranscript(`${HOST} ${COMMITMENT} ${OPENING}`, hexDecode, sha256);
  assert.equal(hexEncode(a.hostNonce), HOST);
  assert.equal(hexEncode(b.hostNonce), HOST);
  assert.equal(a.commitmentMatches, true);
  assert.equal(b.commitmentMatches, true);
});

test("two unrelated 32-byte fields are rejected (Jade ρ is not a BitBox commitment)", () => {
  const other = "22".repeat(32);
  assert.throws(
    () => hodlParseBitboxTranscript(`${other} ${HOST} ${OPENING}`, hexDecode, sha256),
    /not SHA256\(host_nonce\)/,
  );
});

test("s2c tweak is tagged_hash(opening || host_nonce), never SHA256(host_nonce)", () => {
  const opening = hexDecode(OPENING);
  const nonce = hexDecode(HOST);
  const tweak = hodlBitboxS2cTweak(sha256, opening, nonce);
  assert.equal(
    hexEncode(tweak),
    "52be4b29692b2aa0d852edd9a5451e8ca2e6759b41c4bf0dc290f99cf145bea2",
  );
  const trap = hodlBitboxS2cTweak(sha256, opening, sha256(nonce));
  assert.notEqual(hexEncode(tweak), hexEncode(trap));
});

test("uncompressed opening is rejected", () => {
  assert.throws(
    () => hodlParseBitboxTranscript(`${HOST} ${"04" + "aa".repeat(32)}`, hexDecode, sha256),
    /compressed secp256k1 point/,
  );
});
