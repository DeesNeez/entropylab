// Match transaction outputs against a session key. Air-gapped: no chain.
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { p2pkh, p2sh, p2tr, p2wpkh, NETWORK, TEST_NETWORK } from "@scure/btc-signer";

export const OWNERSHIP_GAP = 50;
export const OWNERSHIP_ACCOUNTS = 3;

const SCRIPT_TYPES = [
  { id: "bip44", script: "p2pkh", purpose: 44 },
  { id: "bip49", script: "p2sh-p2wpkh", purpose: 49 },
  { id: "bip84", script: "p2wpkh", purpose: 84 },
  { id: "bip86", script: "p2tr", purpose: 86 },
];

function netOf(network) {
  return network === "testnet" ? TEST_NETWORK : NETWORK;
}

function coinType(network) {
  return network === "testnet" ? 1 : 0;
}

function hash160(bytes) {
  return ripemd160(sha256(bytes));
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function bytesToHex(bytes) {
  if (!bytes) return "";
  if (typeof bytes === "string") return bytes.replace(/^0x/i, "").toLowerCase();
  const arr = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, "0");
  return hex;
}

function taggedTapTweak(pubkey) {
  // p2tr script is OP_1 || 32-byte x-only output key. We still prefer scure when it works.
  return pubkey.slice(1);
}

function scriptFor(script, pubkey, network) {
  const compressed = pubkey.length === 33 ? pubkey : null;
  const key = compressed || pubkey;
  if (script === "p2pkh") {
    const hash = hash160(key);
    return concatBytes(Uint8Array.of(0x76, 0xa9, 0x14), hash, Uint8Array.of(0x88, 0xac));
  }
  if (script === "p2wpkh") {
    if (!compressed) return null;
    const hash = hash160(compressed);
    return concatBytes(Uint8Array.of(0x00, 0x14), hash);
  }
  if (script === "p2sh-p2wpkh") {
    if (!compressed) return null;
    const hash = hash160(compressed);
    const redeem = concatBytes(Uint8Array.of(0x00, 0x14), hash);
    const redeemHash = hash160(redeem);
    return concatBytes(Uint8Array.of(0xa9, 0x14), redeemHash, Uint8Array.of(0x87));
  }
  if (script === "p2tr") {
    try {
      const pay = p2tr(taggedTapTweak(compressed || pubkey), undefined, netOf(network));
      return pay.script ? Uint8Array.from(pay.script) : null;
    } catch {
      return null;
    }
  }
  return null;
}

function addressFor(script, pubkey, network) {
  try {
    if (script === "p2pkh") return p2pkh(pubkey, netOf(network)).address;
    if (script === "p2sh-p2wpkh") return p2sh(p2wpkh(pubkey, netOf(network)), netOf(network)).address;
    if (script === "p2wpkh") return p2wpkh(pubkey, netOf(network)).address;
    if (script === "p2tr") return p2tr(pubkey.slice(1), undefined, netOf(network)).address;
  } catch {
    return null;
  }
  return null;
}

export function normalizeAddress(value) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  if (/^(bc1|tb1|bcrt1)/i.test(text)) {
    if (/[A-Z]/.test(text) && /[a-z]/.test(text)) return text;
    return text.toLowerCase();
  }
  return text;
}

export function addressFromPubkey(script, pubkey, network) {
  return addressFor(script, pubkey, network);
}

function remember(map, address, meta) {
  if (address) {
    const key = normalizeAddress(address);
    if (key && !map.has(key)) map.set(key, meta);
  }
  if (meta.scriptHex && !map.has(meta.scriptHex)) map.set(meta.scriptHex, meta);
}

function record(map, definition, pubkey, network, extra) {
  const scriptBytes = scriptFor(definition.script, pubkey, network);
  if (!scriptBytes) return;
  const address = addressFor(definition.script, pubkey, network);
  remember(map, address, {
    ...extra,
    script: definition.script,
    bip: definition.id,
    scriptHex: bytesToHex(scriptBytes),
    address: address || "",
  });
}

export function indexSingleKey(priv, network, getPublicKey) {
  const map = new Map();
  if (!priv || !getPublicKey) return map;
  const compressed = getPublicKey(priv, true);
  const uncompressed = getPublicKey(priv, false);
  for (const definition of SCRIPT_TYPES) record(map, definition, compressed, network, {
    role: "key",
    chain: "key",
    index: null,
    path: "session key",
  });
  record(map, SCRIPT_TYPES[0], uncompressed, network, {
    role: "key",
    chain: "key",
    index: null,
    path: "session key (uncompressed)",
  });
  return map;
}

export function indexHdKey(root, network, options = {}) {
  const map = new Map();
  if (!root) return map;
  const gap = Number.isFinite(options.gap) ? options.gap : OWNERSHIP_GAP;
  const accounts = Number.isFinite(options.accounts) ? options.accounts : OWNERSHIP_ACCOUNTS;
  const coin = coinType(network);
  const scanAccountNode = (node, pathPrefix, account) => {
    for (const definition of SCRIPT_TYPES) {
      for (const [chain, role] of [[0, "receive"], [1, "change"]]) {
        for (let index = 0; index < gap; index++) {
          let child;
          try {
            child = node.derive(`m/${chain}/${index}`);
          } catch {
            continue;
          }
          const pubkey = child.publicKey;
          if (!pubkey) continue;
          record(map, definition, pubkey, network, {
            role,
            chain: role,
            index,
            account,
            path: `${pathPrefix}/${chain}/${index}`,
          });
        }
      }
    }
  };
  if (root.depth && root.depth !== 0) {
    scanAccountNode(root, "m", null);
    return map;
  }
  for (const definition of SCRIPT_TYPES) {
    for (let account = 0; account < accounts; account++) {
      let node;
      try {
        node = root.derive(`m/${definition.purpose}'/${coin}'/${account}'`);
      } catch {
        continue;
      }
      for (const [chain, role] of [[0, "receive"], [1, "change"]]) {
        for (let index = 0; index < gap; index++) {
          let child;
          try {
            child = node.derive(`m/${chain}/${index}`);
          } catch {
            continue;
          }
          const pubkey = child.publicKey;
          if (!pubkey) continue;
          record(map, definition, pubkey, network, {
            role,
            chain: role,
            index,
            account,
            path: `m/${definition.purpose}h/${coin}h/${account}h/${chain}/${index}`,
          });
        }
      }
    }
  }
  return map;
}

export function matchOwnership(map, addressOrScript) {
  if (!map || !map.size) return { state: "no-session" };
  if (addressOrScript instanceof Uint8Array) {
    const hit = map.get(bytesToHex(addressOrScript));
    if (hit) return { state: "ours", ...hit };
    return { state: "external", searched: map.size };
  }
  const key = normalizeAddress(addressOrScript);
  if (!key) return { state: "empty" };
  if (key.startsWith("script ")) {
    const hex = key.slice(7).replace(/\s/g, "").toLowerCase();
    const hit = map.get(hex);
    if (hit) return { state: "ours", ...hit };
  }
  const hit = map.get(key);
  if (!hit) return { state: "external", searched: map.size };
  return { state: "ours", ...hit };
}

export function pathLabel(path) {
  if (!Array.isArray(path)) return "";
  return path.map((index) => (index & 0x80000000) ? `${index & 0x7fffffff}h` : String(index)).join("/");
}

export { SCRIPT_TYPES };
