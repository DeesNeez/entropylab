//! Deterministic vanity-address grinder for EntropyLab.
//!
//! Candidates come from a counter, never from randomness: counter `i` maps to
//! a fixed-width base-62 "odometer" string over the alphabet a-zA-Z0-9 (in
//! that order), and that string is used as a brain-wallet passphrase —
//! `privkey = SHA-256(passphrase)` — from which the selected mainnet address
//! type (P2PKH, P2SH-P2WPKH, P2WPKH, or P2TR) is derived and compared against
//! a caller-supplied prefix. Same counter always yields the same address, so a
//! found passphrase is reproducible by anyone.
//!
//! Session salt: when the caller passes `salt`, the ground passphrase is
//! `salt ++ odometer` (the JS side supplies the session's passphrase
//! verbatim, or — with no passphrase entered — the SHA-256 hex digest of the
//! session's entropy inputs), so the same counters only reproduce while those
//! inputs stay unchanged. An empty salt is the public counter mapping above.
//!
//! Bucketing: a contiguous counter range is a bucket of passphrases sharing
//! leading characters (odometer order), so the JS side splits the search
//! space across Web Workers as disjoint counter ranges with no overlap and no
//! gap. This crate only ever sees one range at a time.
//!
//! The boundary mirrors secp256k1-wasm: one `vanity_grind` call grinds
//! `[start, start + count)` and writes a small header plus fixed-size match
//! records into a caller-owned buffer. Private keys never leave the loop —
//! only the passphrase, counter, and address payload of a *matching* candidate
//! cross into JS (HASH160 for hash-based scripts, x-only output key for P2TR).
//!
//! Output buffer layout (little-endian):
//!   [0..8]    u64 processed   — candidates tested (== count unless the
//!                               record area filled up first)
//!   [8..12]   u32 matches     — number of 72-byte records that follow
//!   [12..]    records: u64 counter | 32-byte passphrase (zero-padded) |
//!                      32-byte address payload
//!
//! Return value: 0 on success, -1 for invalid arguments, -2 when the record
//! area filled up (the header still reports progress; re-enter at
//! `start + processed`).

use ripemd::Ripemd160;
use secp256k1_sys as ffi;
use sha2::{Digest, Sha256};
use std::alloc::{alloc, Layout};
use std::ptr::NonNull;
use std::sync::OnceLock;

// From the pinned vendored include/secp256k1.h (same values as secp256k1-wasm):
// SECP256K1_CONTEXT_SIGN = (1<<0)|(1<<9). Grinding only creates public keys,
// so no verify (ecmult) tables are built.
const CONTEXT_FLAGS: u32 = (1 << 0) | (1 << 9);

struct Context(*mut ffi::Context);
// wasm32-unknown-unknown is single-threaded, so sharing the pointer is sound.
unsafe impl Sync for Context {}
unsafe impl Send for Context {}
static CONTEXT: OnceLock<Context> = OnceLock::new();

fn ctx() -> *const ffi::Context {
    CONTEXT
        .get_or_init(|| unsafe {
            let size = ffi::secp256k1_context_preallocated_size(CONTEXT_FLAGS);
            // 16 matches max_align_t for the wasm32 C ABI.
            let layout = Layout::from_size_align(size, 16).expect("valid context layout");
            let mem = alloc(layout);
            assert!(!mem.is_null(), "context allocation failed");
            let cx = ffi::secp256k1_context_preallocated_create(
                NonNull::new(mem.cast()).expect("allocation is non-null"),
                CONTEXT_FLAGS,
            );
            Context(cx.as_ptr())
        })
        .0
}

/// The passphrase alphabet, in the user-facing order a-zA-Z0-9.
const ALPHABET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc830a3;
const SCRIPT_P2PKH: u32 = 0;
const SCRIPT_P2SH_P2WPKH: u32 = 1;
const SCRIPT_P2WPKH: u32 = 2;
const SCRIPT_P2TR: u32 = 3;

/// Passphrases are at most 32 characters (62^32 dwarfs the u64 counter).
const MAX_PASS_LEN: usize = 32;
/// The session salt is at most 256 bytes (a verbatim passphrase, or a
/// SHA-256 hex digest for entropy-only sessions). The JS worker allocates
/// its salt buffer with the same limit (`MAX_SALT` in vanity-worker.js).
const MAX_SALT_LEN: usize = 256;
/// The longest supported mainnet address is a 62-character Taproot bech32m
/// string. Base58 addresses are shorter and share the same record buffer.
const MAX_ADDR_LEN: usize = 62;
/// counter (8) + passphrase (32) + address payload (32).
const RECORD_LEN: usize = 72;
const HEADER_LEN: usize = 12;

/// Allocates `len` bytes of linear memory for JS to fill. Pair with
/// `vanity_free`.
#[no_mangle]
pub extern "C" fn vanity_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr`/`len` must come from `vanity_alloc`.
#[no_mangle]
pub unsafe extern "C" fn vanity_free(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len));
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(data)).into()
}

/// Base58Check of version + HASH160 (mainnet P2PKH/P2SH), written into the
/// fixed address buffer. Returns the encoded length.
fn base58check_address(version: u8, hash: &[u8; 20]) -> ([u8; MAX_ADDR_LEN], usize) {
    let mut payload = [0u8; 25];
    payload[0] = version;
    payload[1..21].copy_from_slice(hash);
    let checksum = sha256(&sha256(&payload[..21]));
    payload[21..25].copy_from_slice(&checksum[..4]);

    let zeros = payload.iter().take_while(|&&b| b == 0).count();
    // Repeated carry propagation, base 256 -> base 58 (digits little-endian).
    let mut digits = [0u8; 35];
    let mut digit_len = 0usize;
    for &byte in &payload[zeros..] {
        let mut carry = byte as u32;
        for d in digits[..digit_len].iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits[digit_len] = (carry % 58) as u8;
            carry /= 58;
            digit_len += 1;
        }
    }
    let mut out = [0u8; MAX_ADDR_LEN];
    out[..zeros].fill(b'1');
    for k in 0..digit_len {
        out[zeros + k] = B58[digits[digit_len - 1 - k] as usize];
    }
    (out, zeros + digit_len)
}

fn bech32_polymod_step(chk: u32) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let top = chk >> 25;
    let mut next = (chk & 0x1ffffff) << 5;
    for (i, generator) in GEN.iter().enumerate() {
        if (top >> i) & 1 == 1 {
            next ^= generator;
        }
    }
    next
}

/// Witness-version + program as 5-bit bech32 data values (version first).
fn bech32_data_values(version: u8, program: &[u8]) -> ([u8; 53], usize) {
    let mut values = [0u8; 53];
    values[0] = version;
    let mut len = 1usize;
    let mut acc = 0u16;
    let mut bits = 0u8;
    for &byte in program {
        acc = (acc << 8) | byte as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            values[len] = ((acc >> bits) & 31) as u8;
            len += 1;
        }
    }
    if bits > 0 {
        values[len] = ((acc << (5 - bits)) & 31) as u8;
        len += 1;
    }
    (values, len)
}

/// BIP173/BIP350 bech32(m) encode for mainnet witness addresses.
fn bech32_address(version: u8, program: &[u8], bech32m: bool) -> ([u8; MAX_ADDR_LEN], usize) {
    let (values, value_len) = bech32_data_values(version, program);
    let hrp = b"bc";
    let mut chk = 1u32;
    for &c in hrp {
        chk = bech32_polymod_step(chk) ^ (c >> 5) as u32;
    }
    chk = bech32_polymod_step(chk);
    for &c in hrp {
        chk = bech32_polymod_step(chk) ^ (c & 31) as u32;
    }
    for &value in &values[..value_len] {
        chk = bech32_polymod_step(chk) ^ value as u32;
    }
    for _ in 0..6 {
        chk = bech32_polymod_step(chk);
    }
    let polymod = chk ^ if bech32m { BECH32M_CONST } else { 1 };

    let mut out = [0u8; MAX_ADDR_LEN];
    let mut len = 0usize;
    out[len..len + 2].copy_from_slice(hrp);
    len += 2;
    out[len] = b'1';
    len += 1;
    for &value in &values[..value_len] {
        out[len] = BECH32[value as usize];
        len += 1;
    }
    for i in 0..6 {
        let value = (polymod >> (5 * (5 - i))) & 31;
        out[len] = BECH32[value as usize];
        len += 1;
    }
    (out, len)
}

/// BIP86 output key: internal x-only key tweaked by tagged_hash("TapTweak", x).
unsafe fn taproot_output_key(pk: &ffi::PublicKey) -> Option<[u8; 32]> {
    let mut internal = ffi::XOnlyPublicKey::new();
    let mut parity = 0;
    if ffi::secp256k1_xonly_pubkey_from_pubkey(ctx(), &mut internal, &mut parity, pk) != 1 {
        return None;
    }
    let mut internal_bytes = [0u8; 32];
    if ffi::secp256k1_xonly_pubkey_serialize(ctx(), internal_bytes.as_mut_ptr(), &internal) != 1 {
        return None;
    }
    let tag = sha256(b"TapTweak");
    let tweak: [u8; 32] = Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update(internal_bytes)
        .finalize()
        .into();
    let mut output = ffi::PublicKey::new();
    if ffi::secp256k1_xonly_pubkey_tweak_add(ctx(), &mut output, &internal, tweak.as_ptr()) != 1 {
        return None;
    }
    let mut output_xonly = ffi::XOnlyPublicKey::new();
    if ffi::secp256k1_xonly_pubkey_from_pubkey(ctx(), &mut output_xonly, &mut parity, &output) != 1 {
        return None;
    }
    let mut output_bytes = [0u8; 32];
    if ffi::secp256k1_xonly_pubkey_serialize(ctx(), output_bytes.as_mut_ptr(), &output_xonly) != 1 {
        return None;
    }
    Some(output_bytes)
}

/// Grinds counters `[start, start + count)`: counter -> base-62 passphrase of
/// `pass_len` chars -> SHA-256 private key -> the selected address type,
/// recording candidates whose address starts with `prefix`. When `salt_len`
/// is non-zero, the hashed passphrase is `salt ++ passphrase` instead, so the
/// session's inputs prefix every candidate.
///
/// # Safety
/// `prefix`/`prefix_len` must be readable, `salt`/`salt_len` must be readable
/// (or `salt_len == 0`), and `out` must hold `out_cap` writable bytes
/// (>= `HEADER_LEN` + 72 per record capacity desired).
#[no_mangle]
pub unsafe extern "C" fn vanity_grind(
    prefix: *const u8,
    prefix_len: usize,
    pass_len: usize,
    start: u64,
    count: u64,
    out: *mut u8,
    out_cap: usize,
    script: u32,
    salt: *const u8,
    salt_len: usize,
) -> i32 {
    if prefix.is_null() || out.is_null() || prefix_len == 0 || prefix_len > MAX_ADDR_LEN
        || pass_len == 0 || pass_len > MAX_PASS_LEN || out_cap < HEADER_LEN
        || script > SCRIPT_P2TR || salt_len > MAX_SALT_LEN
        || (salt_len > 0 && salt.is_null())
    {
        return -1;
    }
    let prefix = std::slice::from_raw_parts(prefix, prefix_len);
    let salt = if salt_len == 0 { &[][..] } else { std::slice::from_raw_parts(salt, salt_len) };
    let out_slice = std::slice::from_raw_parts_mut(out, out_cap);
    let record_cap = (out_cap - HEADER_LEN) / RECORD_LEN;

    // The counter space for `pass_len` characters, saturating at u64::MAX
    // (62^11 already exceeds it).
    let space = 62u64.checked_pow(pass_len as u32).unwrap_or(u64::MAX);
    let count = count.min(space.saturating_sub(start));

    // Odometer digits (indexes into ALPHABET), most significant first.
    let mut digit = [0u8; MAX_PASS_LEN];
    {
        let mut c = start;
        for i in (0..pass_len).rev() {
            digit[i] = (c % 62) as u8;
            c /= 62;
        }
    }

    let mut processed: u64 = 0;
    let mut matches: u32 = 0;
    let mut pass = [0u8; MAX_PASS_LEN];
    let mut status = 0;

    while processed < count {
        for i in 0..pass_len {
            pass[i] = ALPHABET[digit[i] as usize];
        }
        // Empty salt hashes exactly the odometer string (the public mapping).
        let seckey: [u8; 32] = Sha256::new()
            .chain_update(salt)
            .chain_update(&pass[..pass_len])
            .finalize()
            .into();
        let mut pk = ffi::PublicKey::new();
        // Invalid secret keys (zero or >= group order) are ~2^-128 rare; skip.
        if ffi::secp256k1_ec_pubkey_create(ctx(), &mut pk, seckey.as_ptr()) == 1 {
            let mut serialized = [0u8; 33];
            let mut ser_len = 33usize;
            if ffi::secp256k1_ec_pubkey_serialize(
                ctx(),
                serialized.as_mut_ptr(),
                &mut ser_len,
                &pk,
                ffi::SECP256K1_SER_COMPRESSED,
            ) == 1
            {
                let mut payload = [0u8; 32];
                let candidate = match script {
                    SCRIPT_P2PKH => {
                        let hash = hash160(&serialized);
                        payload[..20].copy_from_slice(&hash);
                        Some(base58check_address(0, &hash))
                    }
                    SCRIPT_P2SH_P2WPKH => {
                        let pubkey_hash = hash160(&serialized);
                        let mut redeem = [0u8; 22];
                        redeem[1] = 20;
                        redeem[2..22].copy_from_slice(&pubkey_hash);
                        let script_hash = hash160(&redeem);
                        payload[..20].copy_from_slice(&pubkey_hash);
                        Some(base58check_address(5, &script_hash))
                    }
                    SCRIPT_P2WPKH => {
                        let hash = hash160(&serialized);
                        payload[..20].copy_from_slice(&hash);
                        Some(bech32_address(0, &hash, false))
                    }
                    _ => taproot_output_key(&pk).map(|output_key| {
                        payload.copy_from_slice(&output_key);
                        bech32_address(1, &output_key, true)
                    }),
                };
                if let Some((addr, addr_len)) = candidate {
                    if addr_len >= prefix_len && &addr[..prefix_len] == prefix {
                        if (matches as usize) < record_cap {
                            let at = HEADER_LEN + matches as usize * RECORD_LEN;
                            out_slice[at..at + 8].copy_from_slice(&(start + processed).to_le_bytes());
                            out_slice[at + 8..at + 8 + MAX_PASS_LEN].fill(0);
                            out_slice[at + 8..at + 8 + pass_len].copy_from_slice(&pass[..pass_len]);
                            out_slice[at + 40..at + 72].copy_from_slice(&payload);
                            matches += 1;
                        } else {
                            status = -2;
                            break;
                        }
                    }
                }
            }
        }
        // Increment the odometer (least significant character last).
        let mut i = pass_len;
        while i > 0 {
            i -= 1;
            digit[i] += 1;
            if digit[i] < 62 {
                break;
            }
            digit[i] = 0;
        }
        processed += 1;
    }

    out_slice[0..8].copy_from_slice(&processed.to_le_bytes());
    out_slice[8..12].copy_from_slice(&matches.to_le_bytes());
    status
}
