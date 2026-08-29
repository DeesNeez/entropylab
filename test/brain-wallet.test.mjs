// Brain-wallet recovery conventions (issue #94): bitaddress.org removed
// boundary-whitespace trimming in v2.9.6, so the exact entered text and the
// trimmed text are different passphrases. EntropyLab offers both conventions
// explicitly and never normalizes silently.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

const hodlBrainWalletPassphrase = new Function(`${loadSlice("hodlBrainWalletPassphrase")}; return hodlBrainWalletPassphrase;`)();

const sha256Hex = (text) => createHash("sha256").update(text, "utf8").digest("hex");

test("exact mode hashes the passphrase exactly as entered (bitaddress.org 2.9.6+)", () => {
  for (const phrase of [" recovery phrase ", "\trecovery phrase\n", "two  spaces", "trail ", " lead"]) {
    assert.equal(hodlBrainWalletPassphrase(phrase, "exact"), phrase);
  }
  // The exact text, not the trimmed text, is the hash input.
  assert.notEqual(sha256Hex(hodlBrainWalletPassphrase(" recovery phrase ", "exact")), sha256Hex("recovery phrase"));
  assert.equal(sha256Hex(hodlBrainWalletPassphrase(" recovery phrase ", "exact")), sha256Hex(" recovery phrase "));
});

test("legacy mode trims boundary whitespace (bitaddress.org before 2.9.6)", () => {
  assert.equal(hodlBrainWalletPassphrase(" recovery phrase ", "legacy"), "recovery phrase");
  assert.equal(hodlBrainWalletPassphrase("\trecovery phrase\n", "legacy"), "recovery phrase");
  // Interior whitespace is preserved under both conventions.
  assert.equal(hodlBrainWalletPassphrase(" two  spaces ", "legacy"), "two  spaces");
  assert.equal(sha256Hex(hodlBrainWalletPassphrase(" recovery phrase ", "legacy")), sha256Hex("recovery phrase"));
});

test("blank passphrases are rejected under both conventions", () => {
  for (const convention of ["exact", "legacy"]) {
    assert.throws(() => hodlBrainWalletPassphrase("", convention), /Enter the brain-wallet passphrase/);
    assert.throws(() => hodlBrainWalletPassphrase("   \n\t ", convention), /Enter the brain-wallet passphrase/);
  }
  // An unknown convention value can never silently trim: only "legacy" trims.
  assert.equal(hodlBrainWalletPassphrase(" x ", "anything-else"), " x ");
});

test("the app defaults to the modern exact-text convention and derives through the selector", () => {
  assert.match(app, /hodlBrainConvention = "exact"/);
  // The private-key builder hashes the selected convention's text.
  assert.match(app, /hodlBrainWalletPassphrase\(e, hodlBrainConvention\)/);
  // The convention picker ships in the private-key form and is disclosed.
  assert.match(app, /id="brain-convention" hidden/);
  assert.match(app, /name="brain-conv" value="exact"/);
  assert.match(app, /name="brain-conv" value="legacy"/);
  assert.match(app, /bitaddress\.org 2\.9\.6\+ \(exact text\)/);
  assert.match(app, /Legacy bitaddress\.org \(before 2\.9\.6\)/);
  // Boundary whitespace is always disclosed in the live status line.
  assert.match(app, /boundary whitespace present \\xB7 kept/);
  assert.match(app, /boundary whitespace present \\xB7 trimmed/);
  // The convention picker is only shown for brain-wallet recovery.
  assert.match(app, /convention\.hidden = kind !== "brain"/);
});

test("WIF, hex, and Mini-key whitespace handling is unchanged", () => {
  // Only the brain branch routes through the convention selector; every
  // other private-key format still parses from the trimmed candidate.
  const brainBranch = app.indexOf('if (r === "brain")');
  const minikeyBranch = app.indexOf('else if (r === "minikey"');
  assert.ok(brainBranch > 0 && minikeyBranch > brainBranch);
  assert.match(app.slice(brainBranch, minikeyBranch), /hodlBrainWalletPassphrase/);
  assert.doesNotMatch(app.slice(minikeyBranch, minikeyBranch + 400), /hodlBrainWalletPassphrase/);
});
