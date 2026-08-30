// Tests for the vanity grinder: the WASM module (src/js/vanity-wasm-b64.js,
// built from vanity-wasm/), the pool helpers (src/js/vanity.js), and the
// shipped worker source (src/js/vanity-worker.js) executed under
// node:worker_threads. Run with `npm test` (part of the default and CI
// suites).
//
// Assurance comes from independent re-derivation: every candidate is
// recomputed from its passphrase with @noble/curves and Node's crypto
// (SHA-256, RIPEMD-160) and matched against the record the WASM produced, so
// the counter → passphrase → private key → address chain is checked at each
// hop. Nothing here is secret; the counters and passphrases are fixed test
// inputs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { secp256k1 as noble } from "@noble/curves/secp256k1.js";
import { createBase58check } from "@scure/base";
import { VANITY_WASM_B64 } from "../src/js/vanity-wasm-b64.js";
import { VANITY_WORKER_SOURCE } from "../src/js/vanity-worker.js";
import {
  VANITY_ALPHABET,
  VanityGrinder,
  estimateVanityWork,
  validateVanityPrefix,
  validateVanityRange,
  vanityAddressFromHash160,
  vanityBuckets,
} from "../src/js/vanity.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const sha256 = (data) => new Uint8Array(createHash("sha256").update(data).digest());
const base58check = createBase58check(sha256);

// Independent derivation of the expected P2PKH address for a passphrase,
// using noble for the curve operation and Node crypto for the hashes.
const expectedAddress = (passphrase) => {
  const seckey = createHash("sha256").update(passphrase, "utf8").digest();
  const pubkey = noble.getPublicKey(new Uint8Array(seckey), true);
  const hash160 = createHash("ripemd160").update(createHash("sha256").update(pubkey).digest()).digest();
  return { address: base58check.encode(new Uint8Array([0, ...new Uint8Array(hash160)])), hash160: new Uint8Array(hash160) };
};

// ── Direct WASM bindings ────────────────────────────────────────────────────

const wasmBytes = (() => {
  const binary = atob(VANITY_WASM_B64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
})();
const wasm = new WebAssembly.Instance(new WebAssembly.Module(wasmBytes), {}).exports;
const heap = () => new Uint8Array(wasm.memory.buffer);

// Runs one vanity_grind call and decodes the out buffer into records.
const grind = (prefix, passLen, start, count, recordCap = 1 << 16) => {
  const prefixBytes = new TextEncoder().encode(prefix);
  const prefixPtr = wasm.vanity_alloc(prefixBytes.length);
  heap().set(prefixBytes, prefixPtr);
  const outCap = 12 + 60 * recordCap;
  const outPtr = wasm.vanity_alloc(outCap);
  try {
    const status = wasm.vanity_grind(prefixPtr, prefixBytes.length, passLen, BigInt(start), BigInt(count), outPtr, outCap);
    const header = new DataView(wasm.memory.buffer, outPtr, 12);
    const processed = header.getBigUint64(0, true);
    const matches = header.getUint32(8, true);
    const records = [];
    for (let i = 0; i < matches; i++) {
      const at = outPtr + 12 + i * 60;
      records.push({
        counter: new DataView(wasm.memory.buffer, at, 8).getBigUint64(0, true),
        passphrase: new TextDecoder().decode(heap().slice(at + 8, at + 8 + passLen)),
        hash160: heap().slice(at + 40, at + 60),
      });
    }
    return { status, processed, matches, records };
  } finally {
    wasm.vanity_free(prefixPtr, prefixBytes.length);
    wasm.vanity_free(outPtr, outCap);
  }
};

test("committed vanity WASM artifact is intact (sha256 in module header matches payload)", () => {
  const source = readFileSync(join(root, "src/js/vanity-wasm-b64.js"), "utf8");
  const declared = source.match(/wasm sha256: ([0-9a-f]{64})/);
  assert.ok(declared, "module header carries the wasm sha256");
  const b64 = source.match(/export const VANITY_WASM_B64 =\s*"([A-Za-z0-9+/=]+)";/);
  assert.ok(b64, "module exports the base64 payload");
  const actual = createHash("sha256").update(Buffer.from(b64[1], "base64")).digest("hex");
  assert.equal(actual, declared[1]);
});

test("committed vanity WASM carries no build-host paths (remapped at build time)", () => {
  const payload = Buffer.from(VANITY_WASM_B64, "base64").toString("latin1");
  for (const banned of ["/home/", "/Users/", ".cargo/", ".rustup/"]) {
    assert.equal(payload.includes(banned), false, `build fingerprints the build host: ${banned}`);
  }
});

test("counter -> passphrase -> address chain matches pinned vectors", () => {
  // Expected addresses derived with noble + Node crypto (see expectedAddress).
  const vectors = [
    { counter: 0n, passLen: 1, passphrase: "a", address: "14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY" },
    { counter: 61n, passLen: 1, passphrase: "9", address: "1JekPe3xZYh3LWLbUH9VZCRp7F1RfF1QAK" },
    { counter: 1000n, passLen: 2, passphrase: "qi", address: "1Bu6KhqJ6qc6dz2Dkf66LgFNzvcMPzziCT" },
    { counter: 0n, passLen: 8, passphrase: "aaaaaaaa", address: "166Ze1gKsnkn9N3iGn3LB3186vS2Unmeb1" },
    { counter: 62n ** 8n - 1n, passLen: 8, passphrase: "99999999", address: "1AwWmZaT27brScSzXvgAHX3MzQn18RkawY" },
  ];
  for (const vector of vectors) {
    const run = grind("1", vector.passLen, vector.counter, 1n);
    assert.equal(run.status, 0);
    assert.equal(run.processed, 1n);
    assert.equal(run.matches, 1); // prefix "1" matches every mainnet P2PKH address
    const record = run.records[0];
    assert.equal(record.counter, vector.counter);
    assert.equal(record.passphrase, vector.passphrase);
    assert.equal(vanityAddressFromHash160(record.hash160), vector.address);
    // ... and the address agrees with the independent derivation.
    assert.equal(expectedAddress(vector.passphrase).address, vector.address);
  }
});

test("the full 1-character space grinds in odometer order over a-zA-Z0-9", () => {
  const run = grind("1", 1, 0n, 62n);
  assert.equal(run.status, 0);
  assert.equal(run.processed, 62n);
  assert.equal(run.matches, 62);
  for (let i = 0; i < 62; i++) {
    assert.equal(run.records[i].counter, BigInt(i));
    assert.equal(run.records[i].passphrase, VANITY_ALPHABET[i], `counter ${i} is alphabet[${i}]`);
    assert.deepEqual(run.records[i].hash160, expectedAddress(VANITY_ALPHABET[i]).hash160);
  }
});

test("a contiguous bucket split is disjoint and equals the full range", () => {
  // 2-character space = 3844 counters; split at 1922 and compare with the
  // single-run result — the property that makes worker buckets correct.
  const full = grind("1", 2, 0n, 3844n);
  const left = grind("1", 2, 0n, 1922n);
  const right = grind("1", 2, 1922n, 3844n - 1922n);
  const joined = [...left.records, ...right.records];
  assert.equal(full.matches, 3844);
  assert.equal(joined.length, full.matches);
  for (let i = 0; i < joined.length; i++) {
    assert.equal(joined[i].counter, full.records[i].counter);
    assert.equal(joined[i].passphrase, full.records[i].passphrase);
    assert.deepEqual(joined[i].hash160, full.records[i].hash160);
  }
});

test("prefix filtering returns only matching addresses", () => {
  const all = grind("1", 1, 0n, 62n);
  const wanted = vanityAddressFromHash160(all.records[7].hash160).slice(0, 2);
  const filtered = grind(wanted, 1, 0n, 62n);
  assert.ok(filtered.matches >= 1 && filtered.matches < 62);
  for (const record of filtered.records) {
    assert.ok(vanityAddressFromHash160(record.hash160).startsWith(wanted));
  }
  assert.ok(filtered.records.some((record) => record.counter === all.records[7].counter));
  const impossible = grind("1zzzzzz", 1, 0n, 62n);
  assert.equal(impossible.status, 0);
  assert.equal(impossible.matches, 0);
});

test("vanity_grind rejects invalid arguments", () => {
  assert.equal(grind("1", 0, 0n, 1n).status, -1, "pass length 0");
  assert.equal(grind("", 1, 0n, 1n).status, -1, "empty prefix");
  assert.equal(grind("1", 33, 0n, 1n).status, -1, "pass length beyond 32");
  // An out buffer too small even for the 12-byte header is invalid.
  const prefixPtr = wasm.vanity_alloc(1);
  heap().set([0x31], prefixPtr);
  const outPtr = wasm.vanity_alloc(8);
  try {
    assert.equal(wasm.vanity_grind(prefixPtr, 1, 1, 0n, 1n, outPtr, 8), -1);
  } finally {
    wasm.vanity_free(prefixPtr, 1);
    wasm.vanity_free(outPtr, 8);
  }
  // A record area too small for every match stops early with -2 and reports
  // how far it got, so the caller can resume at start + processed.
  const tight = grind("1", 1, 0n, 62n, 10);
  assert.equal(tight.status, -2);
  assert.equal(tight.matches, 10);
  assert.equal(tight.processed, 10n);
});

// ── Pool helpers (src/js/vanity.js) ─────────────────────────────────────────

test("vanityBuckets partitions the range without overlap or gap", () => {
  for (const [start, count, workers] of [[0n, 3844n, 3], [10n, 1000n, 7], [0n, 5n, 8], [123n, 1n, 4], [0n, 62n ** 4n, 16]]) {
    const buckets = vanityBuckets(start, count, workers);
    assert.ok(buckets.length >= 1 && buckets.length <= workers);
    let cursor = start;
    for (const bucket of buckets) {
      assert.equal(bucket.start, cursor, "buckets are contiguous");
      assert.ok(bucket.count > 0n, "no empty buckets");
      cursor += bucket.count;
    }
    assert.equal(cursor, start + count, "buckets cover the whole range");
  }
});

test("validateVanityPrefix enforces a base58 prefix beyond the leading 1", () => {
  assert.equal(validateVanityPrefix("1Love"), "1Love");
  assert.throws(() => validateVanityPrefix("Love"), /starts with/);
  assert.throws(() => validateVanityPrefix("1"), /alone matches every address/);
  assert.throws(() => validateVanityPrefix("10"), /base58/); // 0 is not base58
  assert.throws(() => validateVanityPrefix("1O"), /base58/);
  assert.throws(() => validateVanityPrefix("1".repeat(35)), /longer than a whole address/);
});

test("validateVanityRange bounds the counter to the passphrase space (u64)", () => {
  assert.deepEqual(validateVanityRange(1, 0n, 62n), { passLen: 1, start: 0n, count: 62n });
  assert.throws(() => validateVanityRange(1, 61n, 2n), /runs past the 1-character space/); // 61 + 2 > 62^1
  assert.throws(() => validateVanityRange(0, 0n, 1n), /length is 1 to 32/);
  assert.throws(() => validateVanityRange(33, 0n, 1n), /length is 1 to 32/);
  assert.throws(() => validateVanityRange(8, 0n, 0n), /at least one candidate/);
  assert.throws(() => validateVanityRange(8, -1n, 1n), /zero or more/);
  // 62^11 exceeds u64::MAX, so the 64-bit counter is the binding limit.
  assert.deepEqual(validateVanityRange(11, 0n, (1n << 64n) - 1n).count, (1n << 64n) - 1n);
  assert.throws(() => validateVanityRange(11, 0n, 1n << 64n), /64-bit counter/);
});

test("estimateVanityWork is 58^(prefix length - 1)", () => {
  assert.equal(estimateVanityWork("1a"), 58n);
  assert.equal(estimateVanityWork("1ab"), 3364n);
  assert.equal(estimateVanityWork("1abc"), 195112n);
});

test("vanityAddressFromHash160 agrees with the record path", () => {
  const { address, hash160 } = expectedAddress("a");
  assert.equal(vanityAddressFromHash160(hash160), address);
});

// ── Worker protocol (the shipped source, under node:worker_threads) ─────────

// node:worker_threads has no `self`; the prelude adapts the Web Worker
// surface the shipped source expects, so the identical string is what runs.
const NODE_WORKER_PRELUDE = `
const { parentPort } = require("worker_threads");
globalThis.self = globalThis;
globalThis.postMessage = (message) => parentPort.postMessage(message);
parentPort.on("message", (data) => globalThis.self.onmessage({ data }));
`;

class NodeWebWorkerAdapter {
  constructor() {
    this.inner = new Worker(NODE_WORKER_PRELUDE + VANITY_WORKER_SOURCE, { eval: true });
    this.onmessage = null;
    this.onerror = null;
    this.inner.on("message", (data) => this.onmessage?.({ data }));
    this.inner.on("error", (error) => this.onerror?.(error));
  }
  postMessage(message, transfer) {
    this.inner.postMessage(message, transfer);
  }
  terminate() {
    return this.inner.terminate();
  }
}
const nodeSpawn = () => ({ worker: new NodeWebWorkerAdapter(), url: null });

const initWorker = () => new Promise((resolve, reject) => {
  const worker = new NodeWebWorkerAdapter();
  worker.onmessage = (event) => {
    if (event.data?.type === "ready") resolve(worker);
  };
  worker.onerror = (error) => reject(error);
  const copy = wasmBytes.slice().buffer;
  worker.postMessage({ type: "init", wasm: copy }, [copy]);
});

test("worker source: init, grind, progress, done — with a matching hit", async () => {
  const worker = await initWorker();
  try {
    const events = [];
    worker.onmessage = (event) => events.push(event.data);
    worker.postMessage({ type: "grind", prefix: "1", passLen: 1, start: 0n, count: 62n });
    const done = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("worker never finished")), 30000);
      const poll = setInterval(() => {
        const last = events.findLast((message) => message.type === "done");
        if (last) {
          clearInterval(poll);
          clearTimeout(timer);
          resolve(last);
        }
      }, 10);
    });
    assert.equal(done.done, 62n);
    assert.equal(done.stopped, false);
    const matches = events.filter((message) => message.type === "progress").flatMap((message) => message.matches);
    assert.equal(matches.length, 62);
    assert.equal(matches[0].passphrase, "a");
    assert.equal(vanityAddressFromHash160(matches[0].hash160), expectedAddress("a").address);
    assert.ok(events.some((message) => message.type === "progress" && message.done === 62n));
  } finally {
    await worker.terminate();
  }
});

test("worker source: stop ends the run cooperatively", async () => {
  const worker = await initWorker();
  try {
    const events = [];
    worker.onmessage = (event) => {
      events.push(event.data);
      if (event.data?.type === "progress") worker.postMessage({ type: "stop" });
    };
    worker.postMessage({ type: "grind", prefix: "1zzzzz", passLen: 4, start: 0n, count: 20000000n });
    const done = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("worker ignored stop")), 30000);
      const poll = setInterval(() => {
        const last = events.findLast((message) => message.type === "done");
        if (last) {
          clearInterval(poll);
          clearTimeout(timer);
          resolve(last);
        }
      }, 10);
    });
    assert.equal(done.stopped, true);
    assert.ok(done.done < 20000000n, `stop landed early (done=${done.done})`);
  } finally {
    await worker.terminate();
  }
});

test("VanityGrinder pool aggregates buckets across workers", async () => {
  const matches = [];
  let progressEvents = 0;
  const result = await new Promise((resolve, reject) => {
    const grinder = new VanityGrinder({
      onMatch: (match) => matches.push(match),
      onProgress: () => {
        progressEvents += 1;
      },
      onDone: resolve,
      onError: (message) => reject(new Error(message)),
    }, nodeSpawn);
    grinder.start({ prefix: "1", passLen: 2, start: 0n, count: 3844n, workers: 3 });
  });
  assert.equal(result.done, 3844n);
  assert.equal(result.stopped, false);
  assert.equal(result.found, 3844);
  assert.equal(matches.length, 3844);
  assert.ok(progressEvents >= 3, "every worker reported progress");
  const hit = matches.find((match) => match.counter === 1000n);
  assert.equal(hit.passphrase, "qi");
  assert.equal(hit.address, "1Bu6KhqJ6qc6dz2Dkf66LgFNzvcMPzziCT");
});
