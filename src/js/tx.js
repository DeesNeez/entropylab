// Raw Bitcoin transaction parser for EntropyLab inspect.
// Used when the paste is a signed (or unsigned) transaction, not a PSBT.
const ORD_MAGIC = Uint8Array.of(0x00, 0x63, 0x03, 0x6f, 0x72, 0x64); // OP_FALSE OP_IF "ord"

function need(bytes, offset, length, message) {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + length > bytes.length) {
    throw new Error(message || "Transaction ended early.");
  }
}

function readU32(bytes, offset) {
  need(bytes, offset, 4);
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, true);
}

function readU64(bytes, offset) {
  need(bytes, offset, 8, "Transaction ended inside an amount.");
  let value = 0n;
  for (let i = 0; i < 8; i++) value |= BigInt(bytes[offset + i]) << BigInt(8 * i);
  return value;
}

function readVarInt(bytes, offset) {
  need(bytes, offset, 1);
  const first = bytes[offset];
  if (first < 0xfd) return [first, offset + 1];
  if (first === 0xfd) {
    need(bytes, offset + 1, 2);
    const value = bytes[offset + 1] | (bytes[offset + 2] << 8);
    if (value < 0xfd) throw new Error("Non-minimal compact size.");
    return [value, offset + 3];
  }
  if (first === 0xfe) {
    need(bytes, offset + 1, 4);
    const value = readU32(bytes, offset + 1);
    if (value < 0x10000) throw new Error("Non-minimal compact size.");
    return [value, offset + 5];
  }
  throw new Error("Compact size is too large.");
}

function readSlice(bytes, offset) {
  const [length, start] = readVarInt(bytes, offset);
  need(bytes, start, length, "Transaction ended inside a script.");
  return [bytes.slice(start, start + length), start + length];
}

function containsOrdEnvelope(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < ORD_MAGIC.length) return false;
  outer: for (let i = 0; i <= bytes.length - ORD_MAGIC.length; i++) {
    for (let j = 0; j < ORD_MAGIC.length; j++) {
      if (bytes[i + j] !== ORD_MAGIC[j]) continue outer;
    }
    return true;
  }
  return false;
}

function looksLikeDerSig(bytes) {
  if (!bytes || bytes.length < 9 || bytes[0] !== 0x30) return false;
  const body = bytes[1];
  if (body >= 0x80) return false;
  return 2 + body + 1 === bytes.length || 2 + body === bytes.length;
}

function looksLikePubkey(bytes) {
  if (!bytes) return false;
  if (bytes.length === 33 && (bytes[0] === 2 || bytes[0] === 3)) return true;
  if (bytes.length === 65 && bytes[0] === 4) return true;
  return false;
}

export function scriptPushes(script) {
  if (!(script instanceof Uint8Array)) return [];
  const pushes = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i++];
    if (op === 0x00) {
      pushes.push(new Uint8Array());
      continue;
    }
    if (op <= 0x4b) {
      if (i + op > script.length) break;
      pushes.push(script.slice(i, i + op));
      i += op;
      continue;
    }
    if (op === 0x4c) {
      if (i >= script.length) break;
      const length = script[i++];
      if (i + length > script.length) break;
      pushes.push(script.slice(i, i + length));
      i += length;
      continue;
    }
    if (op === 0x4d) {
      if (i + 2 > script.length) break;
      const length = script[i] | (script[i + 1] << 8);
      i += 2;
      if (i + length > script.length) break;
      pushes.push(script.slice(i, i + length));
      i += length;
      continue;
    }
  }
  return pushes;
}

function sigFromBytes(bytes, input) {
  if (!looksLikeDerSig(bytes)) return null;
  const hasSighash = bytes.length === 2 + bytes[1] + 1;
  const der = hasSighash ? bytes.slice(0, -1) : bytes;
  const sighash = hasSighash ? bytes[bytes.length - 1] : 1;
  return { input, der, sighash, raw: bytes, pubkey: null };
}

function collectSigs(items, input, signatures) {
  let pending = null;
  for (const item of items) {
    const sig = sigFromBytes(item, input);
    if (sig) {
      if (pending) signatures.push(pending);
      pending = sig;
      continue;
    }
    if (pending && looksLikePubkey(item)) {
      pending.pubkey = item;
      signatures.push(pending);
      pending = null;
      continue;
    }
  }
  if (pending) signatures.push(pending);
}

export function parseRawTx(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error("Transaction must be bytes.");
  if (bytes.length < 10) throw new Error("That is too short to be a Bitcoin transaction.");
  if (bytes.length > 5e6) throw new Error("This transaction is too large to inspect safely.");
  let offset = 0;
  const version = readU32(bytes, offset);
  offset += 4;
  need(bytes, offset, 1, "Transaction ended before inputs.");
  let segwit = false;
  if (bytes[offset] === 0x00) {
    need(bytes, offset, 2, "Transaction ended inside the witness marker.");
    if (bytes[offset + 1] !== 0x01) throw new Error("Unknown witness flag.");
    segwit = true;
    offset += 2;
  }
  const [inputCount, inputStart] = readVarInt(bytes, offset);
  if (inputCount > 1e5) throw new Error("Transaction has too many inputs.");
  offset = inputStart;
  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    need(bytes, offset, 36, "Transaction ended inside an input.");
    const txid = bytes.slice(offset, offset + 32);
    offset += 32;
    const vout = readU32(bytes, offset);
    offset += 4;
    let scriptSig;
    [scriptSig, offset] = readSlice(bytes, offset);
    need(bytes, offset, 4, "Transaction ended inside an input sequence.");
    const sequence = readU32(bytes, offset);
    offset += 4;
    inputs.push({ txid, vout, scriptSig, sequence, witness: [] });
  }
  const [outputCount, outputStart] = readVarInt(bytes, offset);
  if (outputCount > 1e5) throw new Error("Transaction has too many outputs.");
  offset = outputStart;
  const outputs = [];
  for (let i = 0; i < outputCount; i++) {
    const amount = readU64(bytes, offset);
    offset += 8;
    let script;
    [script, offset] = readSlice(bytes, offset);
    outputs.push({ amount, script });
  }
  if (segwit) {
    for (let i = 0; i < inputs.length; i++) {
      const [stackCount, stackStart] = readVarInt(bytes, offset);
      offset = stackStart;
      const stack = [];
      for (let j = 0; j < stackCount; j++) {
        let item;
        [item, offset] = readSlice(bytes, offset);
        stack.push(item);
      }
      inputs[i].witness = stack;
    }
  }
  need(bytes, offset, 4, "Transaction ended before locktime.");
  const locktime = readU32(bytes, offset);
  offset += 4;
  if (offset !== bytes.length) throw new Error("Transaction contains trailing bytes.");
  return { version, segwit, inputs, outputs, locktime, raw: bytes };
}

export function extractEcdsaSignatures(tx) {
  const signatures = [];
  (tx.inputs || []).forEach((input, index) => {
    collectSigs(scriptPushes(input.scriptSig || new Uint8Array()), index, signatures);
    collectSigs(input.witness || [], index, signatures);
  });
  return signatures;
}

export function inscriptionHints(tx) {
  const hits = [];
  (tx.inputs || []).forEach((input, index) => {
    const scripts = [input.scriptSig, ...(input.witness || [])].filter(Boolean);
    for (const script of scripts) {
      if (containsOrdEnvelope(script)) {
        hits.push({ input: index, bytes: script.length });
        break;
      }
    }
  });
  return hits;
}

export function isPsbtMagic(bytes) {
  return Boolean(bytes && bytes.length >= 5 && bytes[0] === 0x70 && bytes[1] === 0x73 && bytes[2] === 0x62 && bytes[3] === 0x74 && bytes[4] === 0xff);
}

export { containsOrdEnvelope };
