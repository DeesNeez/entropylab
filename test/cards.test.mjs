// Card entropy parsing and bit counts.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist as bip39English } from "@scure/bip39/wordlists/english.js";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

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

const hodlNormalizeCardToken = new Function(`${loadSlice("hodlNormalizeCardToken")}; return hodlNormalizeCardToken;`)();
const hodlFilterCards = new Function(`${loadSlice("hodlFilterCards")}; return hodlFilterCards;`)();
const hodlCardTypedCharactersAllowed = new Function(`${loadSlice("hodlCardTypedCharactersAllowed")}; return hodlCardTypedCharactersAllowed;`)();
const hodlCardWithoutReplacementBits = new Function(`${loadSlice("hodlCardWithoutReplacementBits")}; return hodlCardWithoutReplacementBits;`)();
const hodlSeedLengths = {
  12: { words: 12, bits: 128, bytes: 16, partialWords: 11, candidates: 128 },
  15: { words: 15, bits: 160, bytes: 20, partialWords: 14, candidates: 64 },
  18: { words: 18, bits: 192, bytes: 24, partialWords: 17, candidates: 32 },
  21: { words: 21, bits: 224, bytes: 28, partialWords: 20, candidates: 16 },
  24: { words: 24, bits: 256, bytes: 32, partialWords: 23, candidates: 8 },
};
function hodlSeedConfig(words = 12) {
  return hodlSeedLengths[words];
}
const hodlCardNeeded = new Function(
  "hodlSeedConfig",
  "hodlCardWithoutReplacementBits",
  `${loadSlice("hodlCardNeeded")}; return hodlCardNeeded;`,
)(hodlSeedConfig, hodlCardWithoutReplacementBits);
const hodlParseCards = new Function(
  "hodlCardNeeded",
  "hodlNormalizeCardToken",
  "hodlCardWithoutReplacementBits",
  `${loadSlice("hodlParseCards")}; return hodlParseCards;`,
)(hodlCardNeeded, hodlNormalizeCardToken, hodlCardWithoutReplacementBits);
const Z = (input) => new Uint8Array(createHash("sha256").update(input).digest());
const M = { encode: (bytes) => Buffer.from(bytes).toString("hex") };
const hodlCardsHashInput = new Function(`${loadSlice("hodlCardsHashInput")}; return hodlCardsHashInput;`)();
const hodlCardsEntropy = new Function(
  "hodlSeedConfig",
  "hodlParseCards",
  "Z",
  "TextEncoder",
  "M",
  "hodlCardsHashInput",
  `${loadSlice("hodlCardsEntropy")}; return hodlCardsEntropy;`,
)(hodlSeedConfig, hodlParseCards, Z, TextEncoder, M, hodlCardsHashInput);
const hodlCardRanks = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "T", "J", "Q", "K"];
const hodlCardSuits = [{ code: "S" }, { code: "H" }, { code: "C" }, { code: "D" }];
const hodlCardSelectionState = new Function(
  "hodlCardRanks", "hodlCardSuits",
  `${loadSlice("hodlCardSelectionState")}; return hodlCardSelectionState;`,
)(hodlCardRanks, hodlCardSuits);
const hodlToggleCardChoice = new Function(`${loadSlice("hodlToggleCardChoice")}; return hodlToggleCardChoice;`)();
const hodlSetInputValueAtEnd = new Function(`${loadSlice("hodlSetInputValueAtEnd")}; return hodlSetInputValueAtEnd;`)();
const Ae = Object.freeze(bip39English);
const hodlBip39WordIndex = new Map(Ae.map((word, index) => [word, index]));
function hodlTargetLastWords(value, targetWords) {
  const config = hodlSeedConfig(targetWords);
  const words = value.split(/\s+/).filter(Boolean);
  if (words.length !== config.partialWords) return null;
  const prefixBits = words.map((word) => hodlBip39WordIndex.get(word).toString(2).padStart(11, "0")).join("");
  const checksumBits = config.bits / 32;
  const missingEntropyBits = config.bits - prefixBits.length;
  const candidates = [];
  for (let suffix = 0; suffix < 2 ** missingEntropyBits; suffix++) {
    const entropyBits = prefixBits + suffix.toString(2).padStart(missingEntropyBits, "0");
    const bytes = new Uint8Array(config.bytes);
    for (let index = 0; index < bytes.length; index++) bytes[index] = Number.parseInt(entropyBits.slice(index * 8, index * 8 + 8), 2);
    const checksum = Z(bytes)[0] >> 8 - checksumBits;
    candidates.push(Ae[suffix * 2 ** checksumBits + checksum]);
  }
  return { candidates };
}
const hodlDirectCardFinalRadices = new Function("hodlSeedConfig", `${loadSlice("hodlDirectCardFinalRadices")}; return hodlDirectCardFinalRadices;`)(hodlSeedConfig);
const hodlDirectCardSteps = new Function("hodlSeedConfig", "hodlDirectCardFinalRadices", `${loadSlice("hodlDirectCardSteps")}; return hodlDirectCardSteps;`)(hodlSeedConfig, hodlDirectCardFinalRadices);
const hodlDirectCardSetLabel = new Function(`${loadSlice("hodlDirectCardSetLabel")}; return hodlDirectCardSetLabel;`)();
const hodlDirectCardInstruction = new Function("hodlDirectCardSetLabel", `${loadSlice("hodlDirectCardInstruction")}; return hodlDirectCardInstruction;`)(hodlDirectCardSetLabel);
const hodlHashedCardInstruction = new Function(`${loadSlice("hodlHashedCardInstruction")}; return hodlHashedCardInstruction;`)();
const hodlDirectCardRankValue = new Function(`${loadSlice("hodlDirectCardRankValue")}; return hodlDirectCardRankValue;`)();
const hodlDirectCardSeparator = new Function("hodlSeedConfig", "hodlDirectCardFinalRadices", `${loadSlice("hodlDirectCardSeparator")}; return hodlDirectCardSeparator;`)(hodlSeedConfig, hodlDirectCardFinalRadices);
const hodlFilterDirectCards = new Function("hodlDirectCardSeparator", `${loadSlice("hodlFilterDirectCards")}; return hodlFilterDirectCards;`)(hodlDirectCardSeparator);
const hodlParseDirectCards = new Function(
  "hodlSeedConfig", "hodlDirectCardSteps", "hodlDirectCardRankValue", "hodlDirectCardFinalRadices", "hodlTargetLastWords", "Ae",
  `${loadSlice("hodlParseDirectCards")}; return hodlParseDirectCards;`,
)(hodlSeedConfig, hodlDirectCardSteps, hodlDirectCardRankValue, hodlDirectCardFinalRadices, hodlTargetLastWords, Ae);
const hodlDirectCardsEntropy = new Function(
  "hodlParseDirectCards", "Pn", "Ae", "Er", "M",
  `${loadSlice("hodlDirectCardsEntropy")}; return hodlDirectCardsEntropy;`,
)(hodlParseDirectCards, validateMnemonic, Ae, mnemonicToEntropy, M);

const RANKS = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "T", "J", "Q", "K"];
const SUITS = ["S", "H", "C", "D"];
const DECK = SUITS.flatMap((suit) => RANKS.map((rank) => rank + suit));

test("card tokens normalize 10 and suit glyphs to ASCII", () => {
  assert.equal(hodlNormalizeCardToken("as"), "AS");
  assert.equal(hodlNormalizeCardToken("10h"), "TH");
  assert.equal(hodlNormalizeCardToken("A♠"), "AS");
  assert.equal(hodlNormalizeCardToken("Q♦"), "QD");
  assert.equal(hodlNormalizeCardToken("foo"), "");
});

test("card transcript input normalizes its limited character set", () => {
  assert.equal(hodlFilterCards("as, 10♥;td"), "AS 10H TD");
  assert.equal(hodlFilterCards("as <img>"), "AS IMG");
  assert.equal(hodlFilterCards("AS 2C TD", true), "A\u2660 2\u2663 T\u2666");
  assert.equal(hodlFilterCards("A\u2660 2\u2663 T\u2666", false), "AS 2C TD");
  assert.equal(hodlFilterCards("AS 10H", true), "A\u2660 10\u2665");
  assert.equal(hodlCardTypedCharactersAllowed("aS 10♥, TD"), true);
  assert.equal(hodlCardTypedCharactersAllowed("B"), false);
});

test("unique-card counts cover every BIP39 entropy length", () => {
  assert.ok(hodlCardWithoutReplacementBits(24) < 128);
  assert.ok(hodlCardWithoutReplacementBits(25) >= 128);
  assert.ok(hodlCardWithoutReplacementBits(30) < 160);
  assert.ok(hodlCardWithoutReplacementBits(31) >= 160);
  assert.ok(hodlCardWithoutReplacementBits(38) < 192);
  assert.ok(hodlCardWithoutReplacementBits(39) >= 192);
  assert.ok(hodlCardWithoutReplacementBits(49) < 224);
  assert.ok(hodlCardWithoutReplacementBits(50) >= 224);
  assert.ok(hodlCardWithoutReplacementBits(52) < 256);
  assert.equal(hodlCardNeeded(12).first, 25);
  assert.equal(hodlCardNeeded(15).first, 31);
  assert.equal(hodlCardNeeded(18).first, 39);
  assert.equal(hodlCardNeeded(21).first, 50);
  assert.deepEqual(hodlCardNeeded(24), { first: 52, extra: 6 });
});

test("parse rejects a repeated card in the first shuffle", () => {
  const parsed = hodlParseCards("AS 2C AS", 12);
  assert.deepEqual(parsed.duplicates, ["AS"]);
  assert.deepEqual(parsed.cards, ["AS", "2C"]);
  assert.deepEqual(parsed.duplicateEntries.map(({ start, end }) => [start, end]), [[6, 8]]);
});

test("parse reports exact ranges for invalid card tokens", () => {
  const parsed = hodlParseCards("AS ZZ 2C", 12);
  assert.deepEqual(parsed.invalid, ["ZZ"]);
  assert.deepEqual(parsed.invalidEntries.map(({ start, end }) => [start, end]), [[3, 5]]);
});

test("24-word extra cards may repeat the first shuffle", () => {
  const first = DECK.join(" ");
  const parsed = hodlParseCards(`${first} AS 2C 3D 4H 5S 6C`, 24);
  assert.equal(parsed.duplicates.length, 0);
  assert.equal(parsed.cards.length, 58);
  assert.ok(parsed.bits >= 256);
});

test("hashed transcript is SHA-256 of ASCII codes", () => {
  const transcript = "AS 2C TD";
  const digest = createHash("sha256").update(transcript, "utf8").digest("hex");
  assert.match(app, /Z\(new TextEncoder\(\)\.encode\(hashInput\)\)/);
  assert.equal(hodlParseCards(transcript, 12).hashInput, transcript);
  assert.equal(hodlCardsHashInput(["AS", "2C", "TD"], false), transcript);
  assert.equal(digest.length, 64);
});

test("Ian Coleman hashed cards SHA-256 the suit-symbol transcript", () => {
  assert.equal(hodlCardsHashInput(["AS", "2C", "TD"], true), "A\u2660 2\u2663 T\u2666");
  const cards = DECK.slice(0, 25);
  const ascii = hodlCardsEntropy(cards.join(" "), 12, false);
  const coleman = hodlCardsEntropy(cards.join(" "), 12, true);
  assert.equal(ascii.ok, true);
  assert.equal(coleman.ok, true);
  assert.equal(ascii.method, "cards-sha256");
  assert.equal(coleman.method, "ian-coleman-cards-sha256");
  assert.notEqual(ascii.hex, coleman.hex);
  assert.equal(coleman.hashInput, hodlCardsHashInput(cards, true));
  assert.equal(createHash("sha256").update(coleman.hashInput, "utf8").digest("hex").slice(0, 32), coleman.hex);
});

test("below-threshold card transcripts fail closed and never produce a seed", () => {
  // One card: 52 enumerable candidates must not produce a wallet (issue #85).
  const one = hodlCardsEntropy("AS", 24);
  assert.equal(one.ok, false);
  assert.equal(one.bytes, undefined);
  assert.equal(one.parsed.cards.length, 1);
  assert.match(one.error, /Only 1 of 58 required cards/);
  assert.match(one.error, /trivially enumerable/);
  assert.equal(hodlCardsEntropy("AS AS", 24).ok, false);
  assert.equal(hodlCardsEntropy("ZZ", 24).ok, false);
});

test("entropy thresholds are enforced at the exact boundary for every phrase length", () => {
  // Required counts come from hodlCardWithoutReplacementBits, not constants.
  for (const [words, first, extra] of [[12, 25, 0], [15, 31, 0], [18, 39, 0], [21, 50, 0], [24, 52, 6]]) {
    const needed = hodlCardNeeded(words);
    assert.equal(needed.first, first);
    assert.equal(needed.extra, extra);
    const required = first + extra;
    // 24 words span two shuffles: the first 52 cards come from one deck and
    // the extra cards from a fresh one (repeats across shuffles are allowed).
    const deal = (count) => count <= 52 ? DECK.slice(0, count).join(" ") : `${DECK.join(" ")} ${DECK.slice(0, count - 52).join(" ")}`;
    const below = hodlCardsEntropy(deal(required - 1), words);
    assert.equal(below.ok, false, `${words} words accepted ${required - 1} cards`);
    assert.match(below.error, new RegExp(`Only ${required - 1} of ${required} required cards`));
    const full = hodlCardsEntropy(deal(required), words);
    assert.equal(full.ok, true, `${words} words rejected ${required} cards`);
    assert.equal(full.bytes.length, words / 3 * 4);
  }
});

test("a complete card transcript keeps deriving the expected deterministic seed", () => {
  // 24 words: full deck plus six cards from a second shuffle.
  const transcript = `${DECK.join(" ")} ${DECK.slice(0, 6).join(" ")}`;
  const entropy = hodlCardsEntropy(transcript, 24);
  assert.equal(entropy.ok, true);
  assert.equal(entropy.bytes.length, 32);
  const expected = createHash("sha256").update(transcript, "utf8").digest();
  assert.deepEqual([...entropy.bytes], [...expected.subarray(0, 32)]);
  const mnemonic = entropyToMnemonic(entropy.bytes, bip39English);
  assert.equal(mnemonic.split(" ").length, 24);
  assert.ok(validateMnemonic(mnemonic, bip39English));
});

test("hashed-card controls accept either suit or rank first and filter the other row", () => {
  const needed = { first: 52, extra: 6 };
  const initial = hodlCardSelectionState([], needed);
  assert.equal(initial.suit, "");
  assert.equal(initial.rank, "");
  assert.equal(initial.card, "");
  const suitFirst = hodlCardSelectionState([], needed, "S", "");
  assert.equal(suitFirst.suit, "S");
  assert.deepEqual(suitFirst.compatibleRanks, hodlCardRanks);
  const rankFirst = hodlCardSelectionState(["AS"], needed, "", "A");
  assert.equal(rankFirst.rank, "A");
  assert.deepEqual(rankFirst.compatibleSuits, ["H", "C", "D"]);
});

test("hashed-card suit and rank selections toggle off when clicked again", () => {
  assert.equal(hodlToggleCardChoice("", "S"), "S");
  assert.equal(hodlToggleCardChoice("S", "S"), "");
  assert.equal(hodlToggleCardChoice("", "A"), "A");
  assert.equal(hodlToggleCardChoice("A", "A"), "");
  assert.equal(hodlToggleCardChoice("S", "H"), "H");
});

test("card undo restores focus and places the caret after the rewritten transcript", () => {
  const input = {
    value: "A284 37A2",
    focused: false,
    selection: null,
    focus(options) {
      this.focused = options?.preventScroll === true;
    },
    setSelectionRange(start, end) {
      this.selection = [start, end];
    },
  };
  hodlSetInputValueAtEnd(input, "A284 37A");
  assert.equal(input.value, "A284 37A");
  assert.equal(input.focused, true);
  assert.deepEqual(input.selection, [8, 8]);
});

test("hashed-card controls disable exhausted suits and ranks", () => {
  const needed = { first: 52, extra: 6 };
  const noSpades = hodlCardSelectionState(hodlCardRanks.map((rank) => rank + "S"), needed);
  assert.equal(noSpades.availableSuits.includes("S"), false);
  const noAces = hodlCardSelectionState(hodlCardSuits.map((suit) => "A" + suit.code), needed);
  assert.equal(noAces.availableRanks.includes("A"), false);
});

test("the last suit or rank is forced and the final deck card completes automatically", () => {
  const needed = { first: 52, extra: 6 }, first50 = DECK.filter((card) => card !== "QC" && card !== "KC");
  const forcedSuit = hodlCardSelectionState(first50, needed);
  assert.equal(forcedSuit.suit, "C");
  assert.equal(forcedSuit.rank, "");
  assert.equal(hodlCardSelectionState(first50, needed, forcedSuit.suit, "Q").card, "QC");
  const final = hodlCardSelectionState([...first50, "QC"], needed);
  assert.equal(final.suit, "C");
  assert.equal(final.rank, "K");
  assert.equal(final.card, "KC");
});

test("direct cards use four rank draws for each complete 11-bit word", () => {
  const parsed = hodlParseDirectCards("A A A A A A A 2", 12);
  assert.equal(parsed.wordSlots[0], "abandon");
  assert.equal(parsed.wordSlots[1], "ability");
  assert.deepEqual(hodlDirectCardSteps(24).slice(0, 8), [8, 8, 8, 4, 8, 8, 8, 4]);
});

test("direct-card transcripts group four pulls per word with one separating space", () => {
  assert.equal(hodlFilterDirectCards("a 2,8;4 / 3_7:a-2", 24), "A284 37A2");
  assert.equal(hodlFilterDirectCards("A28437A2", 24), "A284 37A2");
  for (const words of [12, 15, 18, 21, 24]) {
    const config = hodlSeedConfig(words), finalLength = hodlDirectCardFinalRadices(words).length;
    const grouped = hodlFilterDirectCards("a".repeat(config.partialWords * 4 + finalLength), words).split(" ");
    assert.equal(grouped.length, words, `${words}-word group count`);
    assert.deepEqual(grouped.slice(0, -1).map((group) => group.length), Array(config.partialWords).fill(4), `${words}-word full groups`);
    assert.equal(grouped.at(-1).length, finalLength, `${words}-word final group`);
  }
});

test("direct-card final draws adapt to every BIP39 phrase length", () => {
  const expected = new Map([[12, [8, 8, 2]], [15, [8, 8]], [18, [8, 4]], [21, [8, 2]], [24, [8]]]);
  for (const [words, finalRadices] of expected) {
    const config = hodlSeedConfig(words);
    const steps = hodlDirectCardSteps(words);
    assert.deepEqual(steps.slice(-finalRadices.length), finalRadices, `${words}-word final draws`);
    assert.equal(steps.length, config.partialWords * 4 + finalRadices.length);
    const transcript = Array(steps.length).fill("A").join(" ");
    const result = hodlDirectCardsEntropy(transcript, words);
    assert.equal(result.ok, true, `${words}-word direct result`);
    assert.equal(result.bytes.length, config.bytes);
    assert.equal(validateMnemonic(result.mnemonic, Ae), true);
  }
});

test("card notices give only the physical action required before the next draw", () => {
  let direct = hodlParseDirectCards("", 24);
  assert.equal(hodlDirectCardInstruction(direct), "Shuffle A–8 (any suit) before the first draw.");
  direct = hodlParseDirectCards("A A A", 24);
  assert.equal(hodlDirectCardInstruction(direct), "Shuffle A–4 (any suit) before the next draw.");

  const needed = { first: 52, extra: 6 };
  assert.equal(hodlHashedCardInstruction({ cards: [], needed }), "Shuffle a standard 52-card deck before the first draw.");
  assert.equal(hodlHashedCardInstruction({ cards: ["AS"], needed }), "Deal the next card without replacement from the shuffled deck.");
  assert.equal(hodlHashedCardInstruction({ cards: DECK, needed }), "Shuffle the full 52-card deck again before the next draw.");
  assert.equal(hodlHashedCardInstruction({ cards: [...DECK, "AS"], needed }), "Deal the next card without replacement from the second shuffle.");
  assert.equal(hodlHashedCardInstruction({ cards: [...DECK, "AS", "2S", "3S", "4S", "5S", "6S"], needed }), "");
});

test("direct cards enforce the rank set for the current draw", () => {
  const fourthDraw = hodlParseDirectCards("A A A 5", 24);
  assert.equal(fourthDraw.invalidEntries.length, 1);
  assert.equal(fourthDraw.invalidEntries[0].max, 4);
  const finalDraw = hodlParseDirectCards(`${Array(44).fill("A").join(" ")} A A 3`, 12);
  assert.equal(finalDraw.invalidEntries.at(-1).max, 2);
  assert.equal(hodlDirectCardsEntropy("A", 24).ok, false);
});
