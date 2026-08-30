// BitBox02 anti-klepto transcript parse.
// Mix is secp256k1-zkp s2c (same tagged hash as Jade) but the host first
// sends SHA256(host_nonce). Pasting that commitment as Jade ρ is the trap.
// Inspect only. No signing.

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function eq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let different = 0;
  for (let i = 0; i < a.length; i++) different |= a[i] ^ b[i];
  return different === 0;
}

export function hodlBitboxTaggedSha256(sha256, tag, ...chunks) {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concatBytes(tagHash, tagHash, ...chunks));
}

export function hodlBitboxS2cTweak(sha256, opening, hostNonce) {
  return hodlBitboxTaggedSha256(sha256, "s2c/ecdsa/point", opening, hostNonce);
}

export function hodlParseBitboxTranscript(raw, hexDecode, sha256) {
  if (!raw || !String(raw).trim()) return null;
  const text = String(raw).replace(/0x/gi, "");
  const tokens = text.split(/[^0-9a-fA-F]+/).filter((token) => token.length);
  const thirtyTwo = [];
  const openings = [];
  for (const token of tokens) {
    if (token.length === 64) thirtyTwo.push(hexDecode(token.toLowerCase()));
    else if (token.length === 66) {
      const opening = hexDecode(token.toLowerCase());
      if (opening[0] !== 2 && opening[0] !== 3) {
        throw new Error("BitBox signer commitment must be a compressed secp256k1 point.");
      }
      openings.push(opening);
    } else if (token.length < 64) continue;
    else throw new Error("BitBox anti-klepto wants 32-byte host fields and a 33-byte compressed opening, as hex.");
  }
  if (!openings.length) throw new Error("BitBox anti-klepto needs the 33-byte signer opening R.");
  if (openings.length !== 1) throw new Error("Paste one BitBox signer opening.");
  if (!thirtyTwo.length) throw new Error("BitBox anti-klepto needs the revealed 32-byte host nonce.");

  let hostNonce = null;
  let commitment = null;
  if (thirtyTwo.length === 1) {
    hostNonce = thirtyTwo[0];
    commitment = sha256(hostNonce);
  } else if (thirtyTwo.length === 2) {
    const a = thirtyTwo[0];
    const b = thirtyTwo[1];
    const aHash = sha256(a);
    const bHash = sha256(b);
    if (eq(aHash, b)) {
      hostNonce = a;
      commitment = b;
    } else if (eq(bHash, a)) {
      hostNonce = b;
      commitment = a;
    } else {
      throw new Error("The two 32-byte BitBox fields are not SHA256(host_nonce) and host_nonce. Do not paste a Jade ρ here.");
    }
  } else {
    throw new Error("Paste the BitBox host nonce, optional SHA256 commitment, and one opening.");
  }

  return {
    hostNonce,
    commitment,
    opening: openings[0],
    commitmentMatches: eq(sha256(hostNonce), commitment),
  };
}
