// Lifecycle clearing must discard application state, not only visible fields.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const start = app.indexOf("function hodlInitSecretFieldAutoClear()");
const end = app.indexOf("\nfunction hodlBoot()", start);
const lifecycle = app.slice(start, end);

test("page lifecycle clearing replaces every cached key and clears PSBT private state", () => {
  assert.match(lifecycle, /hodlPsbtWipeMem\(\)/);
  assert.match(lifecycle, /hodlBip85WipeMem\(\)/);
  assert.match(lifecycle, /hodlSpWipeMem\(\)/);
  assert.match(lifecycle, /hodlKeys\s*=\s*hodlKeys\.map\(\(state\)\s*=>\s*\{/);
  assert.match(lifecycle, /privateKeys\[kind\]\s*=\s*""/);
  assert.match(lifecycle, /if \(id !== "privateKeys"\) fields\[id\] = ""/);
  assert.match(lifecycle, /state\.result\s*=\s*null/);
  assert.match(lifecycle, /return hodlNewKeyState\(state\.name, state\.id, state\.number\)/);
  assert.match(lifecycle, /re\s*=\s*null[\s\S]*Ge\s*=\s*false[\s\S]*ft\s*=\s*""[\s\S]*hodlDiceCoinPositions\s*=\s*\[\]/);
  assert.match(lifecycle, /addEventListener\("pagehide", clearSecretFields\)/);
  assert.match(lifecycle, /event\.persisted\) clearSecretFields\(\)/);
});

test("PSBT key and passphrase fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("psbt-key"\)/);
  assert.match(lifecycle, /getElementById\("psbt-pass"\)/);
  assert.match(lifecycle, /psbtKey\.value\s*=\s*""/);
  assert.match(lifecycle, /psbtPass\.value\s*=\s*""/);
});

test("BIP-85 parent and derived-child fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("bip85-key"\)/);
  assert.match(lifecycle, /bip85Key\.value\s*=\s*""/);
  assert.match(lifecycle, /bip85Out\.innerHTML\s*=\s*""/);
});

test("Silent Payments session key and passphrase fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("sp-key"\)/);
  assert.match(lifecycle, /getElementById\("sp-pass"\)/);
  assert.match(lifecycle, /spKey\.value\s*=\s*""/);
  assert.match(lifecycle, /spPass\.value\s*=\s*""/);
});

test("Silent Payments private-bearing inputs and revealed output are cleared", () => {
  // #sp-send-vins carries per-input private keys; #sp-out renders revealed
  // scan/spend private material. Both must go when the page lifecycle clears.
  assert.match(lifecycle, /getElementById\("sp-send-vins"\)/);
  assert.match(lifecycle, /spVins\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-out"\)/);
  assert.match(lifecycle, /spOut\.innerHTML\s*=\s*""/);
  assert.match(lifecycle, /spError\.textContent\s*=\s*""/);
  assert.match(lifecycle, /spSession\.textContent\s*=\s*hodlSpNote/);
});
