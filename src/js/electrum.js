// Electrum Seed Version System (Electrum 2.0+).
//
// Native Electrum phrases are not BIP39. The version prefix is the leading
// hex of HMAC-SHA512("Seed version", normalized_phrase); the seed bytes are
// PBKDF2-HMAC-SHA512(phrase, "electrum"+passphrase, 2048, 64). Derivation is
// Electrum-native — never BIP44/49/84/86:
//   version 01  Standard   m/0/i receive, m/1/i change, compressed P2PKH
//   version 100 SegWit     m/0'/0/i receive, m/0'/1/i change, native P2WPKH
//
// Port of spesmilo/electrum mnemonic.py + version.py + keystore.from_seed.
// Restore does not need a wordlist; EntropyLab still requires BIP39 English
// words so a mistyped token is caught before HMAC. Generation grinds a
// user-supplied integer (no Math.random) until the HMAC prefix matches.

import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { wordlist as bip39English } from "@scure/bip39/wordlists/english.js";
import { validateMnemonic } from "@scure/bip39";

const utf8 = new TextEncoder();
const WORDLIST = bip39English;
const VERSION_KEY = utf8.encode("Seed version");
const SEED_SALT_PREFIX = utf8.encode("electrum");

export const ELECTRUM_GRIND_LIMIT = 100000;
export const ELECTRUM_TARGET_BITS = 132;

// Electrum version.py + keystore.from_seed. SegWit (and 2FA user keys) sit
// at the hardened m/0' node Electrum serializes as a SLIP-132 zpub.
export const ELECTRUM_PREFIXES = Object.freeze({
  "01": Object.freeze({
    prefix: "01",
    id: "standard",
    label: "Standard",
    title: "Electrum Standard",
    script: "p2pkh",
    slip: "x",
    accountId: "electrum-standard",
    twoFactor: false,
    accountPath: "m",
    originPath: ""
  }),
  "100": Object.freeze({
    prefix: "100",
    id: "segwit",
    label: "SegWit",
    title: "Electrum SegWit",
    script: "p2wpkh",
    slip: "z",
    accountId: "electrum-segwit",
    twoFactor: false,
    accountPath: "m/0'",
    originPath: "0h"
  }),
  "101": Object.freeze({
    prefix: "101",
    id: "2fa",
    label: "2FA",
    title: "Electrum 2FA",
    script: "p2pkh",
    slip: "x",
    accountId: "electrum-2fa",
    twoFactor: true,
    accountPath: "m/0'",
    originPath: "0h"
  }),
  "102": Object.freeze({
    prefix: "102",
    id: "2fa_segwit",
    label: "SegWit 2FA",
    title: "Electrum SegWit 2FA",
    script: "p2wpkh",
    slip: "z",
    accountId: "electrum-2fa-segwit",
    twoFactor: true,
    accountPath: "m/0'",
    originPath: "0h"
  })
});

// Same CJK intervals Electrum uses to drop spaces between Asian characters.
const CJK_INTERVALS = [
  [0x4E00, 0x9FFF], [0x3400, 0x4DBF], [0x20000, 0x2A6DF], [0x2A700, 0x2B73F],
  [0x2B740, 0x2B81F], [0xF900, 0xFAFF], [0x2F800, 0x2FA1D], [0x3190, 0x319F],
  [0x2E80, 0x2EFF], [0x2F00, 0x2FDF], [0x31C0, 0x31EF], [0x2FF0, 0x2FFF],
  [0xE0100, 0xE01EF], [0x3100, 0x312F], [0x31A0, 0x31BF], [0xFF00, 0xFFEF],
  [0x3040, 0x309F], [0x30A0, 0x30FF], [0x31F0, 0x31FF], [0x1B000, 0x1B0FF],
  [0xAC00, 0xD7AF], [0x1100, 0x11FF], [0xA960, 0xA97F], [0xD7B0, 0xD7FF],
  [0x3130, 0x318F], [0xA4D0, 0xA4FF], [0x16F00, 0x16F9F], [0xA000, 0xA48F],
  [0xA490, 0xA4CF]
];

export function isCjkCodePoint(code) {
  for (const [min, max] of CJK_INTERVALS) if (code >= min && code <= max) return true;
  return false;
}

export function normalizeElectrumText(value) {
  let seed = String(value ?? "").normalize("NFKD").toLowerCase();
  seed = [...seed].filter((character) => !/\p{M}/u.test(character)).join("");
  seed = seed.split(/\s+/).filter(Boolean).join(" ");
  const chars = [...seed];
  seed = chars.filter((character, index) => {
    if (!/\s/.test(character) || index === 0 || index === chars.length - 1) return true;
    return !(isCjkCodePoint(chars[index - 1].codePointAt(0)) && isCjkCodePoint(chars[index + 1].codePointAt(0)));
  }).join("");
  return seed;
}

function concatBytes(left, right) {
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}

export function electrumVersionHex(phrase) {
  const normalized = normalizeElectrumText(phrase);
  return bytesToHex(hmac(sha512, VERSION_KEY, utf8.encode(normalized)));
}

export function electrumVersionPrefix(phrase) {
  const hex = electrumVersionHex(phrase);
  const length = Number.parseInt(hex[0], 16) + 2;
  return { hex, prefix: hex.slice(0, length), normalized: normalizeElectrumText(phrase) };
}

export function detectElectrumSeed(phrase) {
  const words = normalizeElectrumText(phrase).split(" ").filter(Boolean);
  if (!words.length) return null;
  const { hex, prefix, normalized } = electrumVersionPrefix(words.join(" "));
  const type = ELECTRUM_PREFIXES[prefix];
  if (!type) return null;
  return { ...type, hex, prefix, normalized, words, wordCount: words.length };
}

export function electrumMnemonicToSeed(phrase, passphrase = "") {
  const mnemonic = utf8.encode(normalizeElectrumText(phrase));
  const extension = utf8.encode(normalizeElectrumText(passphrase ?? ""));
  return pbkdf2(sha512, mnemonic, concatBytes(SEED_SALT_PREFIX, extension), { c: 2048, dkLen: 64 });
}

export function electrumMnemonicEncode(value, wordlist = WORDLIST) {
  const n = BigInt(wordlist.length);
  let i = BigInt(value);
  if (i <= 0n) return "";
  const words = [];
  while (i) {
    words.push(wordlist[Number(i % n)]);
    i /= n;
  }
  return words.join(" ");
}

export function electrumMnemonicDecode(phrase, wordlist = WORDLIST) {
  const n = BigInt(wordlist.length);
  const words = normalizeElectrumText(phrase).split(" ").filter(Boolean);
  const indexOf = new Map(wordlist.map((word, index) => [word, index]));
  let i = 0n;
  while (words.length) {
    const index = indexOf.get(words.pop());
    if (index == null) throw new Error("Electrum encode used a word that is not on the English list.");
    i = i * n + BigInt(index);
  }
  return i;
}

export function entropyBytesToInt(bytes, bits = ELECTRUM_TARGET_BITS) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new Error("Electrum generation needs user-supplied entropy bytes.");
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) + BigInt(byte);
  const have = BigInt(bytes.length * 8);
  const want = BigInt(bits);
  if (have > want) value >>= have - want;
  return value;
}

export function grindElectrumSeed(entropyInt, prefix, options = {}) {
  const type = ELECTRUM_PREFIXES[prefix];
  if (!type || type.twoFactor) throw new Error("Electrum generation supports Standard (01) and SegWit (100) only.");
  const wordlist = options.wordlist ?? WORDLIST;
  const limit = options.limit ?? ELECTRUM_GRIND_LIMIT;
  const skipBip39 = options.skipBip39 !== false;
  const start = BigInt(entropyInt);
  for (let nonce = 1; nonce <= limit; nonce++) {
    const integer = start + BigInt(nonce);
    const phrase = electrumMnemonicEncode(integer, wordlist);
    if (!phrase) continue;
    if (electrumMnemonicDecode(phrase, wordlist) !== integer) throw new Error("Electrum mnemonic encode/decode mismatch.");
    if (phrase.split(" ").length !== 12) continue;
    if (skipBip39 && validateMnemonic(phrase, wordlist)) continue;
    const detected = detectElectrumSeed(phrase);
    if (detected?.prefix === prefix) return { phrase, nonce, integer, detected };
  }
  throw new Error(`Could not grind an Electrum ${type.label} seed from this entropy within ${limit} tries. Provide different entropy.`);
}

export function electrumAccountDefinition(detected) {
  const type = detected?.prefix ? ELECTRUM_PREFIXES[detected.prefix] : detected;
  if (!type) throw new Error("Unknown Electrum seed version.");
  const scriptLabel = type.script === "p2wpkh" ? "native P2WPKH (bc1q…)" : "compressed P2PKH (1…)";
  const receivePath = type.accountPath === "m" ? "m/0/i" : "m/0h/0/i";
  const changePath = type.accountPath === "m" ? "m/1/i" : "m/0h/1/i";
  return {
    id: type.accountId,
    bip: "Electrum",
    label: type.title,
    short: type.title,
    beginner: type.twoFactor
      ? `Native Electrum ${type.label} seed. This wallet is 2-of-2 with a TrustedCoin cosigner that EntropyLab does not have, so the addresses below are the user key alone (at ${type.accountPath === "m" ? "m" : "m/0h"}) and will not match the 2FA P2SH/P2WSH wallet.`
      : `Native Electrum seed. Receive ${receivePath} and change ${changePath} as ${scriptLabel}. This is not BIP44/BIP84.`,
    script: type.script,
    purpose: null,
    slip: type.slip,
    accountPath: type.accountPath,
    originPath: type.originPath
  };
}
