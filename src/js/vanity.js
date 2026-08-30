// Vanity address grinding: a counter is the passphrase.
//
// Counter i maps to a fixed-width base-62 "odometer" string over
// a-zA-Z0-9 ("aaa…", "aab…", …), that string is the brain-wallet passphrase
// (private key = SHA-256 of the passphrase), and the legacy P2PKH address is
// checked against a user-chosen prefix. Everything is deterministic — same
// counter, same address — so this is a calculator over a user-chosen range,
// not an entropy source.
//
// Buckets: the counter space splits into contiguous ranges, and because the
// encoding is an odometer, each range is a bucket of passphrases sharing
// leading characters. One Web Worker grinds one range at a time; workers are
// spawned from an inline Blob source so the shipped file stays self-contained
// (CSP worker-src blob:).
import { sha256 } from "@noble/hashes/sha2.js";
import { createBase58check } from "@scure/base";
import { VANITY_WASM_B64 } from "./vanity-wasm-b64.js";
import { VANITY_WORKER_SOURCE } from "./vanity-worker.js";

export const VANITY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
export const VANITY_MAX_PASS_LEN = 32;
export const VANITY_MAX_PREFIX_LEN = 34;
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

// A vanity prefix is base58 and must start with the mainnet P2PKH "1".
// "1" alone would match every address, so at least one more character is
// required to keep results meaningful (and the result buffer bounded).
export function validateVanityPrefix(prefix) {
  const value = String(prefix ?? "").trim();
  if (!value.startsWith("1")) throw new Error("A legacy P2PKH address starts with \u201C1\u201D; the prefix must too.");
  if (value.length < 2) throw new Error("Add at least one character after the leading \u201C1\u201D — \u201C1\u201D alone matches every address.");
  if (value.length > VANITY_MAX_PREFIX_LEN) throw new Error(`The prefix is longer than a whole address (${VANITY_MAX_PREFIX_LEN} characters).`);
  if (!/^1[1-9A-HJ-NP-Za-km-z]+$/.test(value)) throw new Error("Addresses are base58: no 0 (zero), O, I, or l characters.");
  return value;
}

// Expected candidates per matching address: each base58 character beyond the
// leading "1" is one of 58 possibilities.
export function estimateVanityWork(prefix) {
  return 58n ** BigInt(prefix.length - 1);
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

export function vanityAddressFromHash160(hash160) {
  return base58check.encode(new Uint8Array([0, ...hash160]));
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
// address }), onDone({ done, stopped, found }), onError(message).
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

  start({ prefix, passLen, start, count, workers }) {
    // Any previous run is hard-terminated; its late messages are dropped via
    // the run id so they cannot corrupt the new run's totals.
    this.#terminate();
    const runId = ++this.runId;
    const total = count;
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
          worker.postMessage({ type: "grind", prefix, passLen, start: bucket.start, count: bucket.count });
        } else if (msg.type === "progress") {
          progress[index] = msg.done;
          for (const match of msg.matches) {
            found += 1;
            this.callbacks.onMatch?.({ counter: match.counter, passphrase: match.passphrase, address: vanityAddressFromHash160(match.hash160) });
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

  #terminate() {
    for (const worker of this.workers) worker.terminate();
    for (const url of this.urls) URL.revokeObjectURL(url);
    this.workers = [];
    this.urls = [];
    this.running = false;
  }
}
