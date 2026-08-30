// BIP370 PSBT v2: synthesize the unsigned tx the inspector already walks.
// Depends on the same helpers the v0 parser uses (passed in).

export function hodlPsbtVersion(entries, hodlR32) {
  const found = entries.filter((entry) => entry.type === 251 && entry.keydata.length === 0);
  if (!found.length) return 0;
  if (found[0].val.length !== 4) throw new Error("PSBT version field is malformed.");
  return hodlR32(found[0].val, 0);
}

export function hodlPsbtGlobalU32(entries, type, label, hodlR32) {
  const found = entries.filter((entry) => entry.type === type && entry.keydata.length === 0);
  if (!found.length) return null;
  if (found[0].val.length !== 4) throw new Error(label + " is malformed.");
  return hodlR32(found[0].val, 0);
}

export function hodlPsbtGlobalCount(entries, type, hodlVarInt) {
  const found = entries.filter((entry) => entry.type === type && entry.keydata.length === 0);
  if (!found.length) return null;
  return hodlVarInt(found[0].val, 0)[0];
}

export function hodlTxFromPsbtV2(global, inputMaps, outputMaps, helpers) {
  const { hodlFind, hodlR32, hodlR64, hodlVarInt } = helpers;
  const version = hodlPsbtGlobalU32(global, 2, "PSBT v2 transaction version", hodlR32);
  if (version === null) throw new Error("A PSBT v2 is missing the transaction version.");
  let locktime = hodlPsbtGlobalU32(global, 3, "PSBT v2 fallback locktime", hodlR32);
  if (locktime === null) locktime = 0;
  const declaredInputs = hodlPsbtGlobalCount(global, 4, hodlVarInt);
  const declaredOutputs = hodlPsbtGlobalCount(global, 5, hodlVarInt);
  if (declaredInputs !== null && declaredInputs !== inputMaps.length) {
    throw new Error("PSBT v2 input count does not match the number of input maps.");
  }
  if (declaredOutputs !== null && declaredOutputs !== outputMaps.length) {
    throw new Error("PSBT v2 output count does not match the number of output maps.");
  }
  const inputs = inputMaps.map((entries, index) => {
    const txidEntry = hodlFind(entries, 14).find((entry) => entry.keydata.length === 0);
    const voutEntry = hodlFind(entries, 15).find((entry) => entry.keydata.length === 0);
    if (!txidEntry || txidEntry.val.length !== 32) throw new Error("PSBT v2 input " + index + " is missing a previous txid.");
    if (!voutEntry || voutEntry.val.length !== 4) throw new Error("PSBT v2 input " + index + " is missing an output index.");
    const seqEntry = hodlFind(entries, 16).find((entry) => entry.keydata.length === 0);
    let sequence = 0xffffffff;
    if (seqEntry) {
      if (seqEntry.val.length !== 4) throw new Error("PSBT v2 input " + index + " sequence is malformed.");
      sequence = hodlR32(seqEntry.val, 0);
    }
    return { txid: txidEntry.val, vout: hodlR32(voutEntry.val, 0), script: new Uint8Array(), sequence };
  });
  const outputs = outputMaps.map((entries, index) => {
    const amountEntry = hodlFind(entries, 3).find((entry) => entry.keydata.length === 0);
    const scriptEntry = hodlFind(entries, 4).find((entry) => entry.keydata.length === 0);
    if (!amountEntry || amountEntry.val.length !== 8) throw new Error("PSBT v2 output " + index + " is missing an amount.");
    if (!scriptEntry) throw new Error("PSBT v2 output " + index + " is missing a script.");
    return { amount: hodlR64(amountEntry.val, 0), script: scriptEntry.val };
  });
  return { version, inputs, outputs, locktime };
}
