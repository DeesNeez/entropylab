// Electrum Seed Version System: HMAC prefix, PBKDF2 salt "electrum", native paths.
// Official restore vectors are from spesmilo/electrum 4.4.6:
//   electrum/tests/test_mnemonic.py  (SEED_TEST_CASES, Test_seeds)
//   electrum/tests/test_wallet_vertical.py (addresses + xpub/zpub)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHmac, pbkdf2Sync, createHash } from "node:crypto";
import { HDKey } from "@scure/bip32";
import { hex, createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { p2pkh, p2wpkh, NETWORK } from "@scure/btc-signer";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist as bip39English } from "@scure/bip39/wordlists/english.js";
import {
  detectElectrumSeed,
  electrumMnemonicToSeed,
  electrumVersionHex,
  electrumVersionPrefix,
  normalizeElectrumText,
  grindElectrumSeed,
  entropyBytesToInt,
  electrumMnemonicEncode,
  electrumMnemonicDecode,
  electrumAccountDefinition,
  ELECTRUM_GRIND_LIMIT,
  ELECTRUM_PREFIXES
} from "../src/js/electrum.js";

const base58check = createBase58check(sha256);
const ZPUB = 78792518;
const ZPRV = 78791436;

function slipEncode(xkey, version) {
  const payload = new Uint8Array(base58check.decode(xkey));
  payload[0] = version >>> 24 & 255;
  payload[1] = version >>> 16 & 255;
  payload[2] = version >>> 8 & 255;
  payload[3] = version & 255;
  return base58check.encode(payload);
}

// spesmilo/electrum test_wallet_vertical.py — Standard (SEED_PREFIX = 01)
const STANDARD = "cycle rocket west magnet parrot shuffle foot correct salt library feed song";
const STANDARD_XPUB = "xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U";
const STANDARD_XPRV = "xprv9s21ZrQH143K32jECVM729vWgGq4mUDJCk1ozqAStTphzQtCTuoFmFafNoG1g55iCnBTXUzz3zWnDb5CVLGiFvmaZjuazHDL8a81cPQ8KL6";
const STANDARD_RECEIVE = "1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf";
const STANDARD_CHANGE = "1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D";

// spesmilo/electrum test_wallet_vertical.py — SegWit (SEED_PREFIX_SW = 100)
const SEGWIT = "bitter grass shiver impose acquire brush forget axis eager alone wine silver";
const SEGWIT_ZPUB = "zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ";
const SEGWIT_ZPRV = "zprvAZswDvNeJeha8qZ8g7efN3FXYVJLaEUsE9TW6qXDEbVe74AZ75c2sZFZXPNFzxnhChDQ89oC8C5AjWwHmH1HeRKE1c4kKBQAmjUDdKDUZw2";
const SEGWIT_RECEIVE = "bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af";
const SEGWIT_CHANGE = "bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p";

// spesmilo/electrum test_mnemonic.py SEED_TEST_CASES['english']
const WILD = "wild father tree among universe such mobile favorite target dynamic credit identify";
const WILD_SEED = "aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e3064342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756";
const WILD_PASSPHRASE = "Did you ever hear the tragedy of Darth Plagueis the Wise?";
const WILD_PASS_SEED = "4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f";

// spesmilo/electrum test_mnemonic.py Test_seeds.mnemonics
const CRAM = "cram swing cover prefer miss modify ritual silly deliver chunk behind inform able";
const TWOFA = "science dawn member doll dutch real can brick knife deny drive list";
const FROST = "frost pig brisk excite novel report camera enlist axis nation novel desert";
const BIP39_ONLY = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Dual-valid (BIP39 checksum AND Electrum HMAC 01). Not an official Electrum fixture.
const DUAL = "stem grief above melody toward security cool congress begin stone tag vocal";
const GENERATED_STANDARD = "year grief above melody toward security cool congress begin stone tag vocal";
const GENERATED_SEGWIT = "hockey group above melody toward security cool congress begin stone tag vocal";

function pythonHmacHex(phrase) {
  return createHmac("sha512", "Seed version").update(normalizeElectrumText(phrase), "utf8").digest("hex");
}

function pythonSeed(phrase, passphrase = "") {
  const mnemonic = normalizeElectrumText(phrase);
  const salt = Buffer.concat([Buffer.from("electrum"), Buffer.from(normalizeElectrumText(passphrase), "utf8")]);
  return pbkdf2Sync(mnemonic, salt, 2048, 64, "sha512").toString("hex");
}

function walletFromPhrase(phrase) {
  const detected = detectElectrumSeed(phrase);
  const seed = electrumMnemonicToSeed(phrase);
  const root = HDKey.fromMasterSeed(seed);
  const accountPath = detected.accountPath || "m";
  const node = accountPath === "m" ? root : root.derive(accountPath);
  const encode = detected.script === "p2wpkh" ? p2wpkh : p2pkh;
  return {
    detected,
    seed: hex.encode(seed),
    fingerprint: (root.fingerprint >>> 0).toString(16).padStart(8, "0"),
    rootXpub: root.publicExtendedKey,
    rootXprv: root.privateExtendedKey,
    accountXpub: node.publicExtendedKey,
    accountXprv: node.privateExtendedKey,
    receive: encode(node.derive("m/0/0").publicKey, NETWORK).address,
    change: encode(node.derive("m/1/0").publicKey, NETWORK).address
  };
}

test("normalize_text collapses whitespace, lowercases, and strips combining marks", () => {
  assert.equal(normalizeElectrumText("  STEM   Grief\tABOVE  "), "stem grief above");
  assert.equal(normalizeElectrumText("Café"), "cafe");
});

test("HMAC-SHA512 Seed version matches Electrum prefixes from test_mnemonic.py", () => {
  for (const phrase of [STANDARD, SEGWIT, WILD, CRAM, TWOFA, FROST, BIP39_ONLY]) {
    assert.equal(electrumVersionHex(phrase), pythonHmacHex(phrase));
  }
  assert.equal(detectElectrumSeed(STANDARD).prefix, "01");
  assert.equal(detectElectrumSeed(SEGWIT).prefix, "100");
  assert.equal(detectElectrumSeed(WILD).prefix, "100");
  assert.equal(detectElectrumSeed(CRAM).prefix, "01");
  assert.equal(detectElectrumSeed(TWOFA).prefix, "101");
  assert.equal(detectElectrumSeed(FROST).prefix, "100");
  assert.equal(detectElectrumSeed(BIP39_ONLY), null);
  assert.equal(electrumVersionPrefix(STANDARD).prefix, "01");
  assert.equal(electrumVersionPrefix(SEGWIT).prefix, "100");
});

test("PBKDF2 salt is electrum+passphrase (Electrum test_mnemonic.py english vector)", () => {
  assert.equal(hex.encode(electrumMnemonicToSeed(WILD)), WILD_SEED);
  assert.equal(hex.encode(electrumMnemonicToSeed(WILD)), pythonSeed(WILD));
  assert.equal(hex.encode(electrumMnemonicToSeed(WILD, WILD_PASSPHRASE)), WILD_PASS_SEED);
  assert.equal(hex.encode(electrumMnemonicToSeed(WILD, WILD_PASSPHRASE)), pythonSeed(WILD, WILD_PASSPHRASE));
  assert.notEqual(WILD_SEED, WILD_PASS_SEED);
  // Electrum Test_NewMnemonic.test_mnemonic_to_seed_basic (not a valid seed)
  assert.equal(
    hex.encode(electrumMnemonicToSeed("foobar", "none")),
    "741b72fd15effece6bfe5a26a52184f66811bd2be363190e07a42cca442b1a5bb22b3ad0eb338197287e6d314866c7fba863ac65d3f156087a5052ebc7157fce"
  );
});

test("version 01 restores compressed P2PKH at m/0/0 and m/1/0 (Electrum test_wallet_vertical)", () => {
  const wallet = walletFromPhrase(STANDARD);
  assert.equal(wallet.detected.id, "standard");
  assert.equal(wallet.detected.accountPath, "m");
  assert.equal(wallet.receive, STANDARD_RECEIVE);
  assert.equal(wallet.change, STANDARD_CHANGE);
  assert.equal(wallet.rootXpub, STANDARD_XPUB);
  assert.equal(wallet.rootXprv, STANDARD_XPRV);
  assert.equal(electrumAccountDefinition(wallet.detected).script, "p2pkh");
});

test("version 100 restores native P2WPKH at m/0h/0/0 and m/0h/1/0 (Electrum test_wallet_vertical)", () => {
  const wallet = walletFromPhrase(SEGWIT);
  assert.equal(wallet.detected.id, "segwit");
  assert.equal(wallet.detected.accountPath, "m/0'");
  assert.equal(wallet.receive, SEGWIT_RECEIVE);
  assert.equal(wallet.change, SEGWIT_CHANGE);
  assert.equal(slipEncode(wallet.accountXpub, ZPUB), SEGWIT_ZPUB);
  assert.equal(slipEncode(wallet.accountXprv, ZPRV), SEGWIT_ZPRV);
  assert.notEqual(wallet.receive, p2wpkh(HDKey.fromMasterSeed(electrumMnemonicToSeed(SEGWIT)).derive("m/0/0").publicKey, NETWORK).address);
  assert.equal(electrumAccountDefinition(wallet.detected).script, "p2wpkh");
});

test("the same BIP39 words through BIP39 vs Electrum produce different masters", () => {
  assert.equal(validateMnemonic(BIP39_ONLY, bip39English), true);
  assert.equal(detectElectrumSeed(BIP39_ONLY), null);
  const bip39Seed = mnemonicToSeedSync(BIP39_ONLY, "");
  const electrumSeed = electrumMnemonicToSeed(BIP39_ONLY);
  assert.notEqual(hex.encode(bip39Seed), hex.encode(electrumSeed));
  assert.notEqual(HDKey.fromMasterSeed(bip39Seed).publicExtendedKey, HDKey.fromMasterSeed(electrumSeed).publicExtendedKey);
  assert.equal((HDKey.fromMasterSeed(bip39Seed).fingerprint >>> 0).toString(16).padStart(8, "0"), "73c5da0a");
});

test("an Electrum phrase that is also BIP39-valid is still detected as Electrum", () => {
  assert.equal(validateMnemonic(DUAL, bip39English), true);
  assert.equal(detectElectrumSeed(DUAL).id, "standard");
  const bip39Fp = (HDKey.fromMasterSeed(mnemonicToSeedSync(DUAL, "")).fingerprint >>> 0).toString(16).padStart(8, "0");
  const electrumFp = (HDKey.fromMasterSeed(electrumMnemonicToSeed(DUAL)).fingerprint >>> 0).toString(16).padStart(8, "0");
  assert.notEqual(bip39Fp, electrumFp);
});

test("2FA prefixes are detected and marked as missing the TrustedCoin cosigner", () => {
  const twofa = detectElectrumSeed(TWOFA);
  assert.equal(twofa.twoFactor, true);
  assert.equal(twofa.prefix, "101");
  assert.equal(twofa.accountPath, "m/0'");
  assert.match(electrumAccountDefinition(twofa).beginner, /TrustedCoin/);
});

test("invalid words and unregistered version prefixes are rejected", () => {
  assert.equal(detectElectrumSeed("cram swing cover prefer miss modify ritual silly deliver chunk behind inform"), null);
  assert.equal(detectElectrumSeed(BIP39_ONLY), null);
  assert.equal(detectElectrumSeed(""), null);
});

test("mnemonic_encode is little-endian remainder over the English list", () => {
  const integer = 123456789n;
  const phrase = electrumMnemonicEncode(integer);
  assert.equal(electrumMnemonicDecode(phrase), integer);
});

test("generation grinds user entropy to prefix 01 or 100 and skips BIP39-valid accidents", () => {
  const entropy = createHash("sha256").update("entropylab-electrum-vector-1").digest();
  const entropyInt = entropyBytesToInt(entropy);
  const standard = grindElectrumSeed(entropyInt, "01");
  assert.equal(standard.phrase, GENERATED_STANDARD);
  assert.equal(standard.nonce, 423);
  assert.equal(validateMnemonic(standard.phrase, bip39English), false);
  assert.equal(standard.detected.prefix, "01");
  const segwit = grindElectrumSeed(entropyInt, "100");
  assert.equal(segwit.phrase, GENERATED_SEGWIT);
  assert.equal(segwit.nonce, 5395);
  assert.equal(validateMnemonic(segwit.phrase, bip39English), false);
  assert.throws(() => grindElectrumSeed(entropyInt, "101"), /Standard \(01\) and SegWit \(100\)/);
});

test("generation never uses Math.random and stays within the grind cap", () => {
  assert.equal(ELECTRUM_GRIND_LIMIT, 100000);
  const src = grindElectrumSeed.toString();
  assert.equal(/Math\.random|getRandomValues/.test(src), false);
});

test("app classifies Electrum before BIP39 and wires native paths, not BIP44/84", () => {
  const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");
  const html = readFileSync(new URL("../src/index.html", import.meta.url), "utf8");
  assert.match(app, /function hodlClassifyMnemonic\(/);
  assert.match(app, /if \(electrum\) return \{ ok: true, words, unknown: \[\], electrum, bip39, format: "electrum" \}/);
  assert.match(app, /id="electrum-seed"/);
  assert.match(app, /will NOT restore as BIP39/);
  assert.match(app, /This phrase will be rejected or produce a different wallet in BIP39-only software/);
  assert.match(app, /Format: \$\{wallet\.electrum/);
  assert.match(app, /Native P2WPKH on m\/0h\/0 and m\/0h\/1/);
  assert.match(app, /accountPath === "m" \? root : root\.derive\(accountPath\)/);
  assert.match(app, /docs\.electrum\.org\/en\/latest\/seedphrase\.html/);
  assert.match(html, /docs\.electrum\.org\/en\/latest\/seedphrase\.html/);
  assert.match(html, /PBKDF2 salt .electrum., not BIP39/);
  assert.equal(ELECTRUM_PREFIXES["01"].accountPath, "m");
  assert.equal(ELECTRUM_PREFIXES["100"].accountPath, "m/0'");
});
