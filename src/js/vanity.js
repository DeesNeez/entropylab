// Vanity address grinding: a counter is the passphrase.
//
// Counter i maps to a fixed-width base-62 "odometer" string over
// a-zA-Z0-9 ("aaa…", "aab…", …), that string is the brain-wallet passphrase
// (private key = SHA-256 of the passphrase), and the selected address type is
// checked against a user-chosen prefix. Everything is deterministic — same
// counter, same address — so this is a calculator over a user-chosen range,
// not an entropy source.
//
// Session salt: when the Key Derivation tab holds a passphrase, that
// passphrase itself prefixes every candidate (vanitySessionSalt below), so a
// found passphrase is the session's passphrase followed by the counter
// characters and reproduces from the passphrase alone. With no passphrase but
// entropy entered, the SHA-256 hex digest of those inputs prefixes every
// candidate instead — the digest, never the inputs themselves, crosses into
// workers and appears in found passphrases.
//
// Buckets: the counter space splits into contiguous ranges, and because the
// encoding is an odometer, each range is a bucket of passphrases sharing
// leading characters. One Web Worker grinds one range at a time; workers are
// spawned from an inline Blob source so the shipped file stays self-contained
// (CSP worker-src blob:).
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { bech32, bech32m, createBase58check } from "@scure/base";
import { VANITY_WASM_B64 } from "./vanity-wasm-b64.js";
import { VANITY_WORKER_SOURCE } from "./vanity-worker.js";

export const VANITY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
export const VANITY_MAX_PASS_LEN = 32;
export const VANITY_MAX_PREFIX_LEN = 62;
const VANITY_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const VANITY_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
export const VANITY_SCRIPTS = Object.freeze({
  "p2pkh": Object.freeze({ code: 0, label: "Legacy P2PKH", prefix: "1", max: 34, bech32: false }),
  "p2sh-p2wpkh": Object.freeze({ code: 1, label: "Nested SegWit P2SH-P2WPKH", prefix: "3", max: 34, bech32: false }),
  "p2wpkh": Object.freeze({ code: 2, label: "Native SegWit P2WPKH", prefix: "bc1q", max: 42, bech32: true }),
  "p2tr": Object.freeze({ code: 3, label: "Taproot P2TR", prefix: "bc1p", max: 62, bech32: true }),
});
// The Rust counter is a u64, so the addressable space saturates at u64::MAX.
const COUNTER_LIMIT = (1n << 64n) - 1n;

const base58check = createBase58check(sha256);

// Decoded once on the main thread; each worker receives its own copy and
// instantiates privately (no shared memory — works without cross-origin
// isolation, including from file://).
const wasmBytes = (() => {
  const binary = atob(VANITY_WASM_B64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
})();

const vanityScript = (script) => VANITY_SCRIPTS[script] ?? VANITY_SCRIPTS.p2pkh;

// A vanity prefix must start with the selected address type's fixed leading
// characters. That fixed prefix alone would match every address of the type,
// so at least one more character is required to keep results meaningful (and
// the result buffer bounded).
export function validateVanityPrefix(prefix, script = "p2pkh") {
  const meta = vanityScript(script);
  let value = String(prefix ?? "").trim();
  if (meta.bech32) value = value.toLowerCase();
  if (!value.startsWith(meta.prefix)) throw new Error(`${meta.label} addresses start with \u201C${meta.prefix}\u201D; the prefix must too.`);
  if (value.length <= meta.prefix.length) throw new Error(`Add at least one character after \u201C${meta.prefix}\u201D — \u201C${meta.prefix}\u201D alone matches every ${meta.label} address.`);
  if (value.length > meta.max) throw new Error(`The prefix is longer than a whole ${meta.label} address (${meta.max} characters).`);
  const alphabet = meta.bech32 ? VANITY_BECH32_ALPHABET : VANITY_BASE58_ALPHABET;
  if (![...value.slice(meta.prefix.length)].every((character) => alphabet.includes(character))) {
    throw new Error(meta.bech32 ? "Bech32 addresses use qpzry9x8gf2tvdw0s3jn54khce6mua7l after the separator (no b, i, o, or 1)." : "Base58 addresses use no 0 (zero), O, I, or l characters.");
  }
  return value;
}

// The salt buffer the WASM side grinds with caps at 256 bytes
// (MAX_SALT_LEN in vanity-wasm/src/lib.rs, MAX_SALT in vanity-worker.js).
export const VANITY_MAX_SALT_LEN = 256;

// Session salt for a grind: the session's passphrase verbatim when one is
// entered, so a found passphrase is that passphrase followed by the counter
// characters and reproduces from the passphrase alone. With no passphrase,
// fall back to the SHA-256 hex digest of the session's non-empty entropy
// inputs in the caller's fixed order — empty inputs are dropped, so the
// digest only changes when an actual value does. With no inputs at all the
// salt is empty and counters map to the public odometer passphrases.
export function vanitySessionSalt(passphrase, values = []) {
  const pass = String(passphrase ?? "");
  if (pass.length) return pass;
  const list = [...values].map((value) => String(value ?? "")).filter((value) => value.length > 0);
  if (!list.length) return "";
  return bytesToHex(sha256(new TextEncoder().encode(JSON.stringify(list))));
}

// A verbatim passphrase can run past the WASM salt buffer, so check before
// spawning workers instead of failing mid-grind.
export function validateVanitySalt(salt) {
  const text = String(salt ?? "");
  const length = new TextEncoder().encode(text).length;
  if (length > VANITY_MAX_SALT_LEN) {
    throw new Error(`The passphrase above is ${length} UTF-8 bytes, over the ${VANITY_MAX_SALT_LEN}-byte vanity salt limit — shorten it, or clear it to salt with a digest of the entropy inputs instead.`);
  }
  return text;
}

// Expected candidates per matching address: each free base58 character is one
// of 58 possibilities; each free bech32 character is one of 32.
export function estimateVanityWork(prefix, script = "p2pkh") {
  const meta = vanityScript(script);
  const free = String(prefix ?? "").length - meta.prefix.length;
  return BigInt(meta.bech32 ? 32 : 58) ** BigInt(Math.max(0, free));
}

export function validateVanityRange(passLen, start, count) {
  if (!Number.isInteger(passLen) || passLen < 1 || passLen > VANITY_MAX_PASS_LEN) {
    throw new Error(`Passphrase length is 1 to ${VANITY_MAX_PASS_LEN} characters.`);
  }
  if (start < 0n || count < 1n) throw new Error("The start counter is zero or more; the range is at least one candidate.");
  const space = 62n ** BigInt(passLen);
  const limit = space < COUNTER_LIMIT ? space : COUNTER_LIMIT;
  if (start >= limit) throw new Error(`The start counter is beyond the ${passLen}-character counter space.`);
  if (start + count > limit) {
    throw new Error(passLen <= 10
      ? `The range runs past the ${passLen}-character space (${limit.toString()} counters).`
      : "The range runs past the 64-bit counter.");
  }
  return { passLen, start, count };
}

// Splits [start, start + count) into `workers` contiguous, disjoint ranges
// covering the whole span — each a bucket of passphrases sharing leading
// characters. The first `count % workers` buckets carry one extra candidate.
export function vanityBuckets(start, count, workers) {
  const n = Math.max(1, Math.min(64, Math.floor(workers) || 1));
  const base = count / BigInt(n);
  const extra = count % BigInt(n);
  const buckets = [];
  let cursor = start;
  for (let i = 0; i < n; i++) {
    const size = base + (BigInt(i) < extra ? 1n : 0n);
    if (size > 0n) buckets.push({ start: cursor, count: size });
    cursor += size;
  }
  return buckets;
}

const vanityHash160 = (bytes) => ripemd160(sha256(bytes));

export function vanityAddressFromHash160(hash160) {
  return base58check.encode(new Uint8Array([0, ...hash160]));
}

// The worker record carries HASH160 for hash-based scripts and the x-only
// output key for P2TR; either way the displayed address is recomputed here.
export function vanityAddressFromRecord(record, script = "p2pkh") {
  const meta = vanityScript(script);
  const payload = record.payload ?? record.hash160;
  if (meta.code === 3) return bech32m.encode("bc", [1, ...bech32m.toWords(payload.slice(0, 32))]);
  const hash160 = payload.slice(0, 20);
  if (meta.code === 1) {
    const redeem = new Uint8Array([0, 20, ...hash160]);
    return base58check.encode(new Uint8Array([5, ...vanityHash160(redeem)]));
  }
  if (meta.code === 2) return bech32.encode("bc", [0, ...bech32.toWords(hash160)]);
  return vanityAddressFromHash160(hash160);
}

// Default spawn: a classic worker from an inline Blob URL, keeping the
// shipped file self-contained (allowed by the CSP's worker-src blob:). The
// URL is revoked when the pool terminates.
const spawnBlobWorker = () => {
  const url = URL.createObjectURL(new Blob([VANITY_WORKER_SOURCE], { type: "text/javascript" }));
  try {
    return { worker: new Worker(url), url };
  } catch (error) {
    URL.revokeObjectURL(url);
    throw error;
  }
};

// One grinding run. Spawns one worker per bucket, streams matches/progress,
// and terminates the pool when the run completes, is stopped, or fails.
// Callbacks: onProgress({ done, total, rate }), onMatch({ counter, passphrase,
// address }), onDone({ done, stopped, found }), onError(message). The reported
// passphrase is the full brain-wallet passphrase: `salt` (the session's
// passphrase verbatim, or the entropy digest fallback; default "") followed
// by the counter odometer string.
// `spawn` is the worker factory; it is injectable so the test suite can run
// this pool under node:worker_threads (which has no Blob URLs).
export class VanityGrinder {
  constructor(callbacks = {}, spawn = spawnBlobWorker) {
    this.callbacks = callbacks;
    this.spawn = spawn;
    this.workers = [];
    this.urls = [];
    this.running = false;
    this.runId = 0;
  }

  start({ prefix, passLen, start, count, workers, script = "p2pkh", salt = "" }) {
    // Any previous run is hard-terminated; its late messages are dropped via
    // the run id so they cannot corrupt the new run's totals.
    this.#terminate();
    const runId = ++this.runId;
    const total = count;
    const scriptCode = vanityScript(script).code;
    const saltText = String(salt ?? "");
    const buckets = vanityBuckets(start, count, workers);
    const progress = new Array(buckets.length).fill(0n);
    let found = 0;
    let finished = 0;
    let failed = false;
    this.running = true;
    this.startedAt = performance.now();

    const finish = (stopped) => {
      if (runId !== this.runId || !this.running) return;
      this.running = false;
      const done = progress.reduce((sum, value) => sum + value, 0n);
      this.callbacks.onDone?.({ done, total, stopped, found });
      this.#terminate();
    };
    const fail = (message) => {
      if (failed) return;
      failed = true;
      this.callbacks.onError?.(message);
      finish(true);
    };

    buckets.forEach((bucket, index) => {
      let spawned;
      try {
        spawned = this.spawn();
      } catch (error) {
        fail(error?.message || "Vanity workers are blocked in this context.");
        return;
      }
      const { worker, url } = spawned;
      if (url) this.urls.push(url);
      this.workers.push(worker);
      worker.onmessage = (event) => {
        if (runId !== this.runId) return;
        const msg = event.data;
        if (!msg || typeof msg !== "object") return;
        if (msg.type === "ready") {
          worker.postMessage({ type: "grind", prefix, passLen, start: bucket.start, count: bucket.count, script: scriptCode, salt: saltText });
        } else if (msg.type === "progress") {
          progress[index] = msg.done;
          for (const match of msg.matches) {
            found += 1;
            this.callbacks.onMatch?.({ counter: match.counter, passphrase: saltText + match.passphrase, payload: match.payload, address: vanityAddressFromRecord(match, script) });
          }
          const done = progress.reduce((sum, value) => sum + value, 0n);
          const elapsed = (performance.now() - this.startedAt) / 1000;
          this.callbacks.onProgress?.({ done, total, rate: elapsed > 0 ? Number(done) / elapsed : 0 });
        } else if (msg.type === "done") {
          progress[index] = msg.done;
          finished += 1;
          if (finished === buckets.length) finish(msg.stopped);
        } else if (msg.type === "error") {
          fail(msg.message || "Vanity worker failed.");
        }
      };
      worker.onerror = (event) => {
        event.preventDefault?.();
        fail(event.message || "Vanity worker failed to start.");
      };
      // Every worker gets a private copy of the module (transferred).
      const copy = wasmBytes.slice().buffer;
      worker.postMessage({ type: "init", wasm: copy }, [copy]);
    });
  }

  stop() {
    for (const worker of this.workers) worker.postMessage({ type: "stop" });
  }

  cancel() {
    this.runId += 1;
    this.#terminate();
  }

  #terminate() {
    for (const worker of this.workers) worker.terminate();
    for (const url of this.urls) URL.revokeObjectURL(url);
    this.workers = [];
    this.urls = [];
    this.running = false;
  }
}
