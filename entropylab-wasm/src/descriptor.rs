//! Output-descriptor evaluation on rust-miniscript, with the BIP390 `musig()`
//! key expression layered on top: rust-miniscript parses descriptors and
//! derives their scripts/addresses (BIP380-386; multipath is refused because
//! one call derives one output), while this module evaluates `musig()`
//! participants itself — BIP327 KeySort + KeyAgg for the aggregate key and
//! BIP328 synthetic-xpub derivation for a `musig(...)/NUM/.../*` suffix —
//! then substitutes the concrete aggregate key and lets rust-miniscript handle
//! the rest. (rust-miniscript's own BIP390 support is still in review:
//! rust-bitcoin/rust-miniscript#954.)
//!
//! The boundary is one export, `el_desc_derive`: descriptor text and a child
//! index in, a newline-separated record out — address (empty when the
//! template has none), scriptPubKey hex, then the comma-separated derived
//! keys (compressed hex) so the caller can enforce its own key-distinctness
//! policy. Everything here is watch-only in effect: xprv/WIF key expressions
//! are accepted (BIP390's vectors use a WIF participant) but are reduced to
//! their public keys immediately; the few secret temporaries live only for
//! the call, like the existing BIP32 path (see the crate doc's residual note).

use crate::{ctx, read, wipe_string};
use bitcoin::bip32::{ChainCode, ChildNumber, Xpub};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::network::NetworkKind;
use bitcoin::{Address, Network, PublicKey as BtcPublicKey, ScriptBuf, WitnessProgram, WitnessVersion};
use bitcoin_hashes::{sha256, Hash, HashEngine};
use miniscript::descriptor::{checksum, DescriptorPublicKey, DescriptorSecretKey, SinglePubKey, Wildcard};
use miniscript::{Descriptor, ForEachKey};
use secp256k1::{PublicKey, Scalar};
use std::str::FromStr;

/// App-built descriptors are under 2 KB; capping the input bounds parse
/// recursion depth ahead of rust-miniscript's own limits.
const MAX_DESCRIPTOR_BYTES: usize = 16_384;

/// BIP328: the synthetic xpub of an aggregate key carries this fixed chain
/// code (SHA-256 of "MuSig2MuSig2MuSig2"), depth 0, child number 0.
const BIP328_CHAIN_CODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76, 0x2d, 0x32, 0xcb, 0x45,
    0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65,
];

/// BIP340/341-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// secp256k1 group order, big-endian.
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6,
    0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Interprets a 32-byte hash as an integer mod n (BIP327's `int(...) mod n`).
/// n is within 2^128 of 2^256, so a single conditional subtraction reduces.
fn scalar_modn(bytes: [u8; 32]) -> Result<Scalar, String> {
    let mut reduced = bytes;
    if reduced >= SECP256K1_ORDER {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let diff = reduced[i] as i16 - SECP256K1_ORDER[i] as i16 - borrow;
            reduced[i] = (diff & 0xff) as u8;
            borrow = if diff < 0 { 1 } else { 0 };
        }
    }
    Scalar::from_be_bytes(reduced).map_err(|_| "key aggregation coefficient out of range".to_string())
}

/// BIP327 KeySort: plain (compressed) keys in lexicographical order.
fn key_sort(keys: &mut [[u8; 33]]) {
    keys.sort();
}

/// BIP327 KeyAgg over plain public keys. The caller sorts first when the
/// order-independent (BIP390) form is required.
fn key_agg(keys: &[[u8; 33]]) -> Result<PublicKey, String> {
    if keys.is_empty() {
        return Err("musig() needs at least one participant key".into());
    }
    let mut list_preimage = Vec::with_capacity(33 * keys.len());
    for key in keys {
        list_preimage.extend_from_slice(key);
    }
    let list_hash = tagged_hash("KeyAgg list", &list_preimage);
    // MuSig2*: the second distinct key gets the constant coefficient 1.
    let second = keys.iter().find(|key| **key != keys[0]).copied();
    let mut sum: Option<PublicKey> = None;
    for key in keys {
        let point = PublicKey::from_slice(key).map_err(|_| "invalid musig() participant public key".to_string())?;
        let coefficient = match second {
            Some(second) if *key == second => Scalar::ONE,
            _ => {
                let mut preimage = Vec::with_capacity(65);
                preimage.extend_from_slice(&list_hash);
                preimage.extend_from_slice(key);
                scalar_modn(tagged_hash("KeyAgg coefficient", &preimage))?
            }
        };
        if coefficient == Scalar::ZERO {
            continue; // contributes the identity element
        }
        let scaled = point
            .mul_tweak(ctx(), &coefficient)
            .map_err(|_| "key aggregation hit the point at infinity".to_string())?;
        sum = Some(match sum {
            None => scaled,
            Some(acc) => acc
                .combine(&scaled)
                .map_err(|_| "key aggregation hit the point at infinity".to_string())?,
        });
    }
    sum.ok_or_else(|| "key aggregation hit the point at infinity".to_string())
}

/// A step in the derivation path that may follow a `musig()` expression.
/// BIP390 allows unhardened steps only (there is no aggregate private key).
enum MusigStep {
    Fixed(u32),
    Wildcard,
}

/// Parses a BIP380 key expression (hex key, xpub/xprv with optional origin
/// and path, or WIF) and reduces secrets to their public half.
fn parse_key_expression(text: &str) -> Result<DescriptorPublicKey, String> {
    match DescriptorSecretKey::from_str(text) {
        Ok(secret) => secret
            .to_public(ctx())
            .map_err(|_| "invalid musig() participant key expression".to_string()),
        Err(_) => DescriptorPublicKey::from_str(text).map_err(|_| "invalid musig() participant key expression".to_string()),
    }
}

/// The compressed encoding of one participant's key. Fixed path steps are
/// applied; a trailing `/*` derives the child at `index` (only allowed when
/// the musig() expression carries no derivation path of its own).
fn participant_public_key(key: &DescriptorPublicKey, index: u32) -> Result<[u8; 33], String> {
    match key {
        DescriptorPublicKey::Single(single) => match single.key {
            SinglePubKey::FullKey(pk) => {
                if !pk.compressed {
                    return Err("uncompressed public keys cannot be musig() participants".into());
                }
                Ok(pk.inner.serialize())
            }
            SinglePubKey::XOnly(xpk) => {
                // An x-only key is its even-y lift (BIP340), compressed form.
                let mut bytes = [0u8; 33];
                bytes[0] = 0x02;
                bytes[1..].copy_from_slice(&xpk.serialize());
                Ok(bytes)
            }
        },
        DescriptorPublicKey::XPub(xkey) => {
            let mut node = xkey.xkey;
            for step in xkey.derivation_path.as_ref() {
                node = node
                    .ckd_pub(ctx(), *step)
                    .map_err(|_| "cannot derive a hardened step from an xpub participant".to_string())?;
            }
            match xkey.wildcard {
                Wildcard::None => {}
                Wildcard::Unhardened => {
                    let child =
                        ChildNumber::from_normal_idx(index).map_err(|_| "derivation index out of range".to_string())?;
                    node = node
                        .ckd_pub(ctx(), child)
                        .map_err(|_| "participant key derivation failed".to_string())?;
                }
                Wildcard::Hardened => {
                    return Err("a hardened wildcard cannot be derived from an xpub participant".into());
                }
            }
            Ok(node.public_key.serialize())
        }
        DescriptorPublicKey::MultiXPub(_) => {
            Err("multipath musig() participants are not supported by this evaluator".into())
        }
    }
}

/// BIP390: the aggregate key for one `musig()` expression at child `index`.
/// Participants are derived, KeySort-ed, and aggregated (BIP327); a trailing
/// `/NUM/.../*` path then derives from the aggregate's BIP328 synthetic xpub.
fn aggregate_musig(inner: &str, suffix: &[MusigStep], index: u32) -> Result<PublicKey, String> {
    let has_suffix = !suffix.is_empty();
    let mut keys: Vec<[u8; 33]> = Vec::new();
    for participant in inner.split(',') {
        if participant.is_empty() {
            return Err("empty musig() participant".into());
        }
        let key = parse_key_expression(participant)?;
        if has_suffix {
            // A ranged musig() derives every child from the aggregate key, so
            // participants must be plain xpub expressions: no wildcard and no
            // multipath of their own, and no raw keys.
            match &key {
                DescriptorPublicKey::XPub(xkey) if xkey.wildcard == Wildcard::None => {}
                DescriptorPublicKey::XPub(_) => {
                    return Err("ranged musig() participants cannot carry their own wildcard".into());
                }
                _ => return Err("ranged musig() requires xpub participants".into()),
            }
        }
        keys.push(participant_public_key(&key, index)?);
    }
    key_sort(&mut keys);
    let mut aggregate = key_agg(&keys)?;
    if has_suffix {
        let mut node = Xpub {
            network: NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0).map_err(|_| "unreachable".to_string())?,
            public_key: aggregate,
            chain_code: ChainCode::from(BIP328_CHAIN_CODE),
        };
        for step in suffix {
            let child = match step {
                MusigStep::Fixed(n) => ChildNumber::from_normal_idx(*n),
                MusigStep::Wildcard => ChildNumber::from_normal_idx(index),
            }
            .map_err(|_| "derivation index out of range".to_string())?;
            node = node
                .ckd_pub(ctx(), child)
                .map_err(|_| "aggregate key derivation failed".to_string())?;
        }
        aggregate = node.public_key;
    }
    Ok(aggregate)
}

/// Parses the `musig(` expression starting at `start` (the byte offset of
/// the "m"), returning its participant text, the suffix steps, and the offset
/// one past the whole expression (suffix included).
fn parse_musig_expr(text: &str, start: usize) -> Result<(String, Vec<MusigStep>, usize), String> {
    let bytes = text.as_bytes(); // ASCII-only, established by verify_checksum
    let open = start + 5;
    if bytes.get(open) != Some(&b'(') {
        return Err("malformed musig() expression".into());
    }
    let mut depth = 1usize;
    let mut i = open + 1;
    let mut close = None;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    let close = close.ok_or_else(|| "unbalanced musig() expression".to_string())?;
    let inner = text[open + 1..close].to_owned();
    if inner.contains("musig(") {
        return Err("musig() cannot be nested".into());
    }
    let (suffix, end) = parse_musig_suffix(text, close + 1)?;
    Ok((inner, suffix, end))
}

/// The x-only aggregate key of one parsed musig() expression at `index`.
fn musig_xonly(inner: &str, suffix: &[MusigStep], index: u32) -> Result<[u8; 32], String> {
    Ok(XOnlyPublicKey::from(aggregate_musig(inner, suffix, index)?).serialize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 15) as u32, 16).unwrap_or('0'));
    }
    out
}

/// Splits an argument list on its top-level commas (a musig() argument
/// contains commas of its own).
fn split_top_level(args: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, ch) in args.char_indices() {
        match ch {
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(&args[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&args[start..]);
    out
}

/// sortedmulti_a(k, keys…) — the tapscript sorted multisig — is not
/// implemented by rust-miniscript (multi_a is, sortedmulti only for
/// sh/wsh), so the keys are derived here, sorted as x-only bytes, and the
/// expression rewritten to the multi_a it denotes. A musig() key expression
/// as a participant is aggregated first (BIP390 allows musig() wherever a
/// key expression is valid).
fn rewrite_sorted_multi_a(args: &str, index: u32) -> Result<String, String> {
    let parts = split_top_level(args);
    if parts.len() < 2 {
        return Err("sortedmulti_a needs a threshold and at least one key".into());
    }
    let threshold = parts[0].trim();
    if threshold.is_empty() || !threshold.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid sortedmulti_a threshold".into());
    }
    let mut keys: Vec<[u8; 32]> = Vec::new();
    for arg in &parts[1..] {
        if arg.is_empty() {
            return Err("empty sortedmulti_a key".into());
        }
        let xonly = if arg.starts_with("musig(") {
            let (mut inner, suffix, end) = parse_musig_expr(arg, 0)?;
            if end != arg.len() {
                return Err("unexpected data after musig() key expression".into());
            }
            let key = musig_xonly(&inner, &suffix, index);
            wipe_string(&mut inner);
            key?
        } else {
            let key = parse_key_expression(arg)?;
            let plain = participant_public_key(&key, index)?;
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&plain[1..]);
            xonly
        };
        keys.push(xonly);
    }
    keys.sort();
    let mut out = format!("multi_a({}", threshold);
    for key in keys {
        out.push(',');
        out.push_str(&hex_lower(&key));
    }
    out.push(')');
    Ok(out)
}

/// Parses the `/NUM/.../*` path that may follow a `musig()`'s closing paren,
/// returning the steps and the offset one past them. Only unhardened steps
/// and a terminal wildcard are allowed (BIP390).
fn parse_musig_suffix(text: &str, mut pos: usize) -> Result<(Vec<MusigStep>, usize), String> {
    let bytes = text.as_bytes();
    let mut steps = Vec::new();
    while bytes.get(pos) == Some(&b'/') {
        pos += 1;
        if bytes.get(pos) == Some(&b'*') {
            pos += 1;
            if matches!(bytes.get(pos), Some(b'h') | Some(b'H') | Some(b'\'')) {
                return Err("musig() child derivation cannot be hardened".into());
            }
            if bytes.get(pos) == Some(&b'/') {
                return Err("the musig() wildcard must be the last derivation step".into());
            }
            steps.push(MusigStep::Wildcard);
            break;
        }
        let start = pos;
        while matches!(bytes.get(pos), Some(b) if b.is_ascii_digit()) {
            pos += 1;
        }
        if start == pos {
            return Err("invalid musig() derivation step".into());
        }
        if matches!(bytes.get(pos), Some(b'h') | Some(b'H') | Some(b'\'')) {
            return Err("musig() derivation steps cannot be hardened".into());
        }
        let step = text[start..pos]
            .parse::<u32>()
            .ok()
            .filter(|n| *n < 0x8000_0000)
            .ok_or_else(|| "musig() derivation step out of range".to_string())?;
        steps.push(MusigStep::Fixed(step));
    }
    if pos < bytes.len() && !matches!(bytes[pos], b',' | b')') {
        return Err("invalid character after musig() expression".into());
    }
    Ok((steps, pos))
}

/// Replaces every `musig(...)` key expression in `body` with the x-only hex
/// of its aggregate key at child `index`, and every `sortedmulti_a(...)`
/// with the multi_a it denotes (keys derived, then sorted as x-only bytes).
/// Key expressions must sit in argument position (after '(', ',', '{', or
/// ':'), which also bars a musig() nested anywhere but as a direct argument;
/// the resulting string is validated by rust-miniscript afterwards.
fn substitute_taproot_exprs(body: &str, index: u32) -> Result<String, String> {
    let mut out = body.to_owned();
    let mut cursor = 0usize;
    loop {
        let hay = &out[cursor..];
        let (start, is_musig) = match (hay.find("musig("), hay.find("sortedmulti_a(")) {
            (Some(m), Some(s)) if m <= s => (cursor + m, true),
            (Some(_), Some(s)) => (cursor + s, false),
            (Some(m), None) => (cursor + m, true),
            (None, Some(s)) => (cursor + s, false),
            (None, None) => break,
        };
        let prev = if start == 0 { None } else { Some(out.as_bytes()[start - 1]) };
        if !matches!(prev, Some(b'(') | Some(b',') | Some(b'{') | Some(b':')) {
            return Err("musig() is a key expression and can only appear where a key is expected".into());
        }
        if is_musig {
            let (mut inner, suffix, end) = parse_musig_expr(&out, start)?;
            let key = musig_xonly(&inner, &suffix, index);
            wipe_string(&mut inner); // a participant can be an xprv/WIF expression
            let replacement = hex_lower(&key?);
            out.replace_range(start..end, &replacement);
            cursor = start + replacement.len();
        } else {
            let open = start + "sortedmulti_a".len();
            let bytes = out.as_bytes();
            let mut depth = 1usize;
            let mut i = open + 1;
            let mut close = None;
            while i < bytes.len() {
                match bytes[i] {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            let close = close.ok_or_else(|| "unbalanced sortedmulti_a() expression".to_string())?;
            let replacement = rewrite_sorted_multi_a(&out[open + 1..close], index)?;
            out.replace_range(start..=close, &replacement);
            cursor = start + replacement.len();
        }
    }
    Ok(out)
}

struct Derived {
    address: Option<String>,
    script_pubkey: ScriptBuf,
    keys: Vec<BtcPublicKey>,
}

/// rawtr() is a raw key-into-output template rust-miniscript does not parse;
/// with a musig() inner key (the BIP390 form) the output is OP_1 <x-only key>
/// with no BIP341 tweak.
fn derive_rawtr(substituted: &str, network: Network) -> Result<Derived, String> {
    let inner = substituted
        .strip_prefix("rawtr(")
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| "malformed rawtr() descriptor".to_string())?;
    let key = XOnlyPublicKey::from_str(inner).map_err(|_| "rawtr() carries a single x-only key".to_string())?;
    let program =
        WitnessProgram::new(WitnessVersion::V1, &key.serialize()).map_err(|_| "invalid rawtr() key".to_string())?;
    let script_pubkey = ScriptBuf::new_witness_program(&program);
    let address = Address::from_script(&script_pubkey, network).ok().map(|a| a.to_string());
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&key.serialize());
    let full = BtcPublicKey::from_slice(&compressed).map_err(|_| "invalid aggregate key".to_string())?;
    Ok(Derived {
        address,
        script_pubkey,
        keys: vec![full],
    })
}

fn derive_miniscript(body: &str, index: u32, network: Network) -> Result<Derived, String> {
    let (descriptor, secrets) = Descriptor::parse_descriptor(ctx(), body).map_err(|e| format!("invalid descriptor: {}", e))?;
    drop(secrets); // parsed xprv/WIF keys; only their public halves are used
    if descriptor.is_multipath() {
        return Err("a multipath descriptor denotes several wallets; derive one branch at a time".into());
    }
    let concrete = descriptor
        .derived_descriptor(ctx(), index)
        .map_err(|_| "descriptor cannot be derived at this index".to_string())?;
    let script_pubkey = concrete.script_pubkey();
    let address = concrete.address(network).ok().map(|a| a.to_string());
    let mut keys = Vec::new();
    concrete.for_each_key(|key| {
        keys.push(*key);
        true
    });
    Ok(Derived {
        address,
        script_pubkey,
        keys,
    })
}

fn derive_descriptor(body: &str, index: u32, network: Network) -> Result<Derived, String> {
    if body.is_empty() || body.len() > MAX_DESCRIPTOR_BYTES {
        return Err("descriptor length out of range".into());
    }
    let has_musig = body.contains("musig(");
    let has_sorted_multi_a = body.contains("sortedmulti_a(");
    if !has_musig && !has_sorted_multi_a {
        return derive_miniscript(body, index, network);
    }
    // BIP390 allows musig() in tr()/rawtr() (sp() is out of scope here);
    // sortedmulti_a() is tapscript-only. Anything else containing either is
    // rejected outright.
    if !body.starts_with("tr(") && !body.starts_with("rawtr(") {
        return Err("musig()/sortedmulti_a() are only allowed inside tr() or rawtr() expressions".into());
    }
    let mut substituted = substitute_taproot_exprs(body, index)?;
    // After substitution a rawtr() must hold exactly one x-only key;
    // anything else (e.g. a rewritten multi_a) fails its parse below.
    let result = if substituted.starts_with("rawtr(") {
        derive_rawtr(&substituted, network)
    } else {
        derive_miniscript(&substituted, index, network)
    };
    wipe_string(&mut substituted);
    result
}

/// Evaluates a descriptor at child `index` and writes the record
/// `address\nscriptPubKeyHex\nkeyHex,keyHex,...` (address empty when the
/// template has none). Returns the record length, -1 on any parse/derivation
/// failure, or -2 when `cap` is too small.
#[no_mangle]
pub unsafe extern "C" fn el_desc_derive(
    desc: *const u8,
    desc_len: usize,
    index: u32,
    net: u8,
    out: *mut u8,
    cap: usize,
) -> i32 {
    let text = match std::str::from_utf8(read(desc, desc_len)) {
        Ok(text) => text,
        Err(_) => return -1,
    };
    let network = match crate::network_from_selector(net) {
        Some(network) => network,
        None => return -1,
    };
    let body = match checksum::verify_checksum(text) {
        Ok(body) => body,
        Err(_) => return -1,
    };
    let derived = match derive_descriptor(body, index, network) {
        Ok(derived) => derived,
        // Error text can embed the failing fragment, and the input may carry
        // xprv/WIF material: wipe before returning the bare -1 sentinel.
        Err(mut error) => {
            wipe_string(&mut error);
            return -1;
        }
    };
    let mut record = String::new();
    if let Some(address) = derived.address {
        record.push_str(&address);
    }
    record.push('\n');
    for byte in derived.script_pubkey.as_bytes() {
        record.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        record.push(char::from_digit((byte & 15) as u32, 16).unwrap_or('0'));
    }
    record.push('\n');
    for (i, key) in derived.keys.iter().enumerate() {
        if i > 0 {
            record.push(',');
        }
        for byte in key.inner.serialize() {
            record.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
            record.push(char::from_digit((byte & 15) as u32, 16).unwrap_or('0'));
        }
    }
    if record.len() > cap {
        wipe_string(&mut record);
        return -2;
    }
    std::ptr::copy_nonoverlapping(record.as_ptr(), out, record.len());
    let len = record.len() as i32;
    wipe_string(&mut record);
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: Network = Network::Bitcoin;

    fn script_hex(body: &str, index: u32) -> String {
        let derived = derive_descriptor(body, index, NET).expect("descriptor derives");
        derived
            .script_pubkey
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    // -- BIP327 key aggregation (bip-0327 vectors/key_agg_vectors.json) ------

    const VK: [&str; 3] = [
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
    ];

    fn key(hex: &str) -> [u8; 33] {
        let mut out = [0u8; 33];
        for i in 0..33 {
            out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex");
        }
        out
    }

    fn agg_xonly(indices: &[usize]) -> String {
        let keys: Vec<[u8; 33]> = indices.iter().map(|&i| key(VK[i])).collect();
        let point = key_agg(&keys).expect("key agg");
        XOnlyPublicKey::from(point)
            .serialize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    #[test]
    fn bip327_key_agg_vectors() {
        assert_eq!(agg_xonly(&[0, 1, 2]), "90539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c");
        assert_eq!(agg_xonly(&[2, 1, 0]), "6204de8b083426dc6eaf9502d27024d53fc826bf7d2012148a0575435df54b2b");
        assert_eq!(agg_xonly(&[0, 0, 0]), "b436e3bad62b8cd409969a224731c193d051162d8c5ae8b109306127da3aa935");
        assert_eq!(agg_xonly(&[0, 0, 1, 1]), "69bc22bfa5d106306e48a20679de1d7389386124d07571d0d872686028c26a3e");
    }

    #[test]
    fn bip328_chain_code_is_the_spec_constant() {
        assert_eq!(BIP328_CHAIN_CODE, sha256::Hash::hash(b"MuSig2MuSig2MuSig2").to_byte_array());
    }

    #[test]
    fn bip328_synthetic_xpub_vectors() {
        // (listed participant order, expected aggregate, expected synthetic xpub)
        let vectors: [(&[&str], &str, &str); 3] = [
            (
                &[
                    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                ],
                "0354240c76b8f2999143301a99c7f721ee57eee0bce401df3afeaa9ae218c70f23",
                "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwXEKGEouzXE6QLLRxjatMcLLzJ5LV5Nib1BN7vJg6yp45yHHRbm",
            ),
            (
                &[VK[0], VK[1], VK[2]],
                "0290539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c",
                "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwVk5TFJk8Tw5WAdV3DhrGfbFA216sE9BsQQiSFTdudkETnKdg8k",
            ),
            (
                &[
                    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                    VK[2],
                    VK[0],
                    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                ],
                "022479f134cdb266141dab1a023cbba30a870f8995b95a91fc8464e56a7d41f8ea",
                "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwUvaZYpysLX4wN59tjwU5pBuDjNrPEJbfxjLwn7ruzbXTcUTHkZ",
            ),
        ];
        for (keys, expected_agg, expected_xpub) in vectors {
            let keys: Vec<[u8; 33]> = keys.iter().map(|k| key(k)).collect();
            let aggregate = key_agg(&keys).expect("key agg");
            assert_eq!(format!("{}", hex33(&aggregate.serialize())), expected_agg.to_lowercase());
            let synthetic = Xpub {
                network: NetworkKind::Main,
                depth: 0,
                parent_fingerprint: Default::default(),
                child_number: ChildNumber::from_normal_idx(0).expect("zero"),
                public_key: aggregate,
                chain_code: ChainCode::from(BIP328_CHAIN_CODE),
            };
            assert_eq!(synthetic.to_string(), expected_xpub);
        }
    }

    fn hex33(bytes: &[u8; 33]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // -- BIP390 musig() descriptor vectors ------------------------------------

    const XA: &str = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
    const XB: &str = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y";

    #[test]
    fn bip390_valid_vectors() {
        // rawtr with a WIF participant: keys are sorted before aggregation.
        assert_eq!(
            script_hex(
                "rawtr(musig(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66))",
                0
            ),
            "5120789d937bade6673538f3e28d8368dda4d0512f94da44cf477a505716d26a1575"
        );
        // tr over raw keys: the aggregate is tweaked (BIP341), unlike rawtr.
        assert_eq!(
            script_hex(
                "tr(musig(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66))",
                0
            ),
            "512079e6c3e628c9bfbce91de6b7fb28e2aec7713d377cf260ab599dcbc40e542312"
        );
        let ranged = format!("rawtr(musig({},{})/0/*)", XA, XB);
        let expected = [
            "51209508c08832f3bb9d5e8baf8cb5cfa3669902e2f2da19acea63ff47b93faa9bfc",
            "51205ca1102663025a83dd9b5dbc214762c5a6309af00d48167d2d6483808525a298",
            "51207dbed1b89c338df6a1ae137f133a19cae6e03d481196ee6f1a5c7d1aeb56b166",
        ];
        for (index, want) in expected.iter().enumerate() {
            assert_eq!(&script_hex(&ranged, index as u32), want, "rawtr ranged index {}", index);
        }
        let internal = format!(
            "tr(musig({},{})/0/*,pk(f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9))",
            XA, XB
        );
        let expected = [
            "51201d377b637b5c73f670f5c8a96a2c0bb0d1a682a1fca6aba91fe673501a189782",
            "51208950c83b117a6c208d5205ffefcf75b187b32512eb7f0d8577db8d9102833036",
            "5120a49a477c61df73691b77fcd563a80a15ea67bb9c75470310ce5c0f25918db60d",
        ];
        for (index, want) in expected.iter().enumerate() {
            assert_eq!(&script_hex(&internal, index as u32), want, "tr internal index {}", index);
        }
        let leaf = format!(
            "tr(f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,pk(musig({},{})/0/*))",
            XA, XB
        );
        let expected = [
            "512068983d461174afc90c26f3b2821d8a9ced9534586a756763b68371a404635cc8",
            "5120368e2d864115181bdc8bb5dc8684be8d0760d5c33315570d71a21afce4afd43e",
            "512097a1e6270b33ad85744677418bae5f59ea9136027223bc6e282c47c167b471d5",
        ];
        for (index, want) in expected.iter().enumerate() {
            assert_eq!(&script_hex(&leaf, index as u32), want, "tr leaf index {}", index);
        }
        // Duplicate participants and fixed participant/musig-level steps.
        assert_eq!(
            script_hex(&format!("tr(musig({0}/1,{0}/1)/2)", XA), 0),
            "5120a17ceacd6422bd5ffd9f165807b254b7d68ad39f179cc4f11545a6835227e97c"
        );
    }

    #[test]
    fn bip390_invalid_vectors_are_rejected() {
        let raw = "musig(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66)";
        // musig() outside tr()/rawtr().
        for wrapper in ["pk", "pkh", "wpkh", "combo"] {
            let body = format!("{}({})", wrapper, raw);
            assert!(derive_descriptor(&body, 0, NET).is_err(), "{}", body);
        }
        for body in [
            format!("sh(wpkh({}))", raw),
            format!("sh(wsh(pk({})))", raw),
            format!("wsh({})", raw),
            format!("sh({})", raw),
        ] {
            assert!(derive_descriptor(&body, 0, NET).is_err(), "{}", body);
        }
        // A ranged musig() requires xpub participants.
        assert!(derive_descriptor(&format!("tr({}/0/0)", raw), 0, NET).is_err());
        // Ranged participants conflict with a ranged musig().
        assert!(derive_descriptor(&format!("tr(musig({}/*,{})/0/*)", XA, XB), 0, NET).is_err());
        // Multipath participants conflict with a multipath musig().
        assert!(derive_descriptor(&format!("tr(musig({}/<0;1>,{})/<2;3>)", XA, XB), 0, NET).is_err());
        // No hardened steps and no hardened child derivation.
        assert!(derive_descriptor(&format!("tr(musig({},{}) /0h/*)", XA, XB).replace(' ', ""), 0, NET).is_err());
        assert!(derive_descriptor(&format!("tr(musig({},{})/0/*h)", XA, XB), 0, NET).is_err());
        // Participants with child derivation conflict with musig()-level steps.
        assert!(derive_descriptor(&format!("tr(musig({}/*,{}/*)/1/2)", XA, XB), 0, NET).is_err());
        // Nesting is forbidden.
        assert!(derive_descriptor(&format!("tr(musig(musig({},{})))", XA, XB), 0, NET).is_err());
    }

    // -- rust-miniscript-backed multisig ---------------------------------------

    #[test]
    fn multisig_descriptors_derive_through_miniscript() {
        // BIP67-sorted 2-of-3 over the BIP327 vector keys, each wrapped form.
        let inner = format!("sortedmulti(2,{},{},{})", VK[0].to_lowercase(), VK[1].to_lowercase(), VK[2].to_lowercase());
        for (wrapper, prefix) in [("sh", "a914"), ("wsh", "0020"), ("sh(wsh", "a914")] {
            let body = if wrapper == "sh(wsh" {
                format!("sh(wsh({}))", inner)
            } else {
                format!("{}({})", wrapper, inner)
            };
            let derived = derive_descriptor(&body, 0, NET).expect("multisig derives");
            assert!(derived.script_pubkey.as_bytes().starts_with(&[0xa9, 0x14]) == prefix.starts_with("a9"));
            assert!(derived.address.is_some());
            assert_eq!(derived.keys.len(), 3);
        }
        // sortedmulti is order-independent; multi preserves the listed order.
        let reversed = format!("sortedmulti(2,{},{},{})", VK[2].to_lowercase(), VK[1].to_lowercase(), VK[0].to_lowercase());
        assert_eq!(script_hex(&format!("wsh({})", inner), 0), script_hex(&format!("wsh({})", reversed), 0));
        let listed = format!("multi(2,{},{},{})", VK[2].to_lowercase(), VK[1].to_lowercase(), VK[0].to_lowercase());
        assert_ne!(script_hex(&format!("wsh({})", inner), 0), script_hex(&format!("wsh({})", listed), 0));
    }

    #[test]
    fn sortedmulti_a_is_derived_sorted_and_matches_the_wallet_vector() {
        // The app's Taproot multisig: NUMS internal key, sortedmulti_a leaf.
        // Expected values are the ones test/msig-address-kinds.test.mjs pins
        // against @scure/btc-signer for secret keys 1, 2, 3.
        let nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
        let keys = [
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        ];
        let desc = format!("tr({},sortedmulti_a(2,{}))", nums, keys.join(","));
        let derived = derive_descriptor(&desc, 0, NET).expect("sortedmulti_a derives");
        assert_eq!(
            derived.address.as_deref(),
            Some("bc1pm5jn9xnjz3v9xm7jjw2yheajy92pps5fdazdpfnmvzfymu787hhs2vktyy")
        );
        // Key order must not matter for sortedmulti_a...
        let mut shuffled = keys;
        shuffled.reverse();
        let desc_rev = format!("tr({},sortedmulti_a(2,{}))", nums, shuffled.join(","));
        assert_eq!(script_hex(&desc, 0), script_hex(&desc_rev, 0));
        // ...but must be preserved by multi_a.
        let listed = format!("tr({},multi_a(2,{}))", nums, shuffled.join(","));
        assert_ne!(script_hex(&desc, 0), script_hex(&listed, 0));
        // testnet rendering uses the same script.
        let testnet = derive_descriptor(&desc, 0, Network::Testnet).expect("testnet derives");
        assert_eq!(
            testnet.address.as_deref(),
            Some("tb1pm5jn9xnjz3v9xm7jjw2yheajy92pps5fdazdpfnmvzfymu787hhsayqy7t")
        );
    }

    #[test]
    fn ranged_xpub_descriptor_matches_bip86_vector() {
        // BIP86's own test key: tr(xpub.../0/*) at index 0 is the published address.
        let body = "tr(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)";
        let derived = derive_descriptor(body, 0, NET).expect("bip86 descriptor");
        assert_eq!(
            derived.address.as_deref(),
            Some("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
        );
    }
}
