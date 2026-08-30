// Source of the vanity grinder Web Worker, shipped as a string so the build
// can spawn workers from a Blob URL inside the single self-contained
// entropylab.html (no separate script file, no network). The same string is
// executed under node:worker_threads by test/vanity-wasm.test.mjs, so what
// ships is what is tested.
//
// Protocol (structured clone; counters are BigInt):
//   main -> worker  { type: "init", wasm: ArrayBuffer }        -> { type: "ready" }
//   main -> worker  { type: "grind", prefix, passLen, start, count }
//   worker -> main  { type: "progress", done, matches }        per chunk
//   worker -> main  { type: "done", done, stopped }            range finished
//   main -> worker  { type: "stop" }                           cooperative stop
//   worker -> main  { type: "error", message }
// Match: { counter: BigInt, passphrase: string, hash160: Uint8Array(20) }.
// The private key (SHA-256 of the passphrase) never leaves the WASM loop.
//
// The string must stay free of backticks and "${" (it lives in a template
// literal below).
export const VANITY_WORKER_SOURCE = `
"use strict";
var wasm = null;
var stopRequested = false;
var prefixPtr = 0;
var outPtr = 0;
var CHUNK = 4096;
var RECORD_CAP = 8192;
var OUT_CAP = 12 + 60 * RECORD_CAP;
var MAX_PREFIX = 34;
var encoder = new TextEncoder();
var decoder = new TextDecoder();

function heap() {
  return new Uint8Array(wasm.memory.buffer);
}

function drain(passLen) {
  var header = new DataView(wasm.memory.buffer, outPtr, 12);
  var processed = header.getBigUint64(0, true);
  var count = header.getUint32(8, true);
  var matches = [];
  for (var i = 0; i < count; i++) {
    var at = outPtr + 12 + i * 60;
    matches.push({
      counter: new DataView(wasm.memory.buffer, at, 8).getBigUint64(0, true),
      passphrase: decoder.decode(heap().slice(at + 8, at + 8 + passLen)),
      hash160: heap().slice(at + 40, at + 60)
    });
  }
  return { processed: processed, matches: matches };
}

function grind(msg) {
  var prefixBytes = encoder.encode(msg.prefix);
  heap().set(prefixBytes, prefixPtr);
  var total = BigInt(msg.count);
  var cursor = BigInt(msg.start);
  var done = BigInt(0);
  stopRequested = false;
  var step = function () {
    if (done >= total || stopRequested) {
      postMessage({ type: "done", done: done, stopped: stopRequested });
      return;
    }
    var remaining = total - done;
    var chunk = remaining > BigInt(CHUNK) ? CHUNK : Number(remaining);
    var status = wasm.vanity_grind(prefixPtr, prefixBytes.length, msg.passLen, cursor, BigInt(chunk), outPtr, OUT_CAP);
    if (status === -1) {
      postMessage({ type: "error", message: "vanity_grind rejected its arguments" });
      return;
    }
    var drained = drain(msg.passLen);
    done += drained.processed;
    cursor += drained.processed;
    postMessage({ type: "progress", done: done, matches: drained.matches });
    // status -2 means the record area filled up; it was drained above, so the
    // loop simply continues. A short chunk means the counter space ran out.
    if (status !== -2 && drained.processed < BigInt(chunk)) {
      postMessage({ type: "done", done: done, stopped: false });
      return;
    }
    setTimeout(step, 0); // yield so a queued "stop" message lands
  };
  step();
}

self.onmessage = function (event) {
  var msg = event.data;
  if (!msg || typeof msg !== "object") return;
  if (msg.type === "init") {
    WebAssembly.instantiate(msg.wasm, {}).then(function (result) {
      wasm = result.instance.exports;
      prefixPtr = wasm.vanity_alloc(MAX_PREFIX);
      outPtr = wasm.vanity_alloc(OUT_CAP);
      postMessage({ type: "ready" });
    }).catch(function (error) {
      postMessage({ type: "error", message: "vanity wasm failed to instantiate: " + (error && error.message || error) });
    });
  } else if (msg.type === "grind") {
    if (!wasm) {
      postMessage({ type: "error", message: "worker not initialized" });
      return;
    }
    try {
      grind(msg);
    } catch (error) {
      postMessage({ type: "error", message: (error && error.message) || String(error) });
    }
  } else if (msg.type === "stop") {
    stopRequested = true;
  }
};
`;
