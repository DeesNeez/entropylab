//! Deterministic vanity-address grinder for EntropyLab.
//!
//! Candidates come from a counter, never from randomness: counter `i` maps to
//! a fixed-width base-62 "odometer" string over the alphabet a-zA-Z0-9 (in
//! that order), and that string is used as a brain-wallet passphrase —
//! `privkey = SHA-256(passphrase)` — from which a legacy mainnet P2PKH
//! address (compressed pubkey, HASH160, Base58Check) is derived and compared
//! against a caller-supplied prefix. Same counter always yields the same
//! address, so a found passphrase is reproducible by anyone.
//!
//! Bucketing: a contiguous counter range is a bucket of passphrases sharing
//! leading characters (odometer order), so the JS side splits the search
//! space across Web Workers as disjoint counter ranges with no overlap and no
//! gap. This crate only ever sees one range at a time.
//!
//! The boundary mirrors secp256k1-wasm: one `vanity_grind` call grinds
//! `[start, start + count)` and writes a small header plus fixed-size match
//! records into a caller-owned buffer. Private keys never leave the loop —
//! only the passphrase, counter, and HASH160 of a *matching* candidate cross
//! into JS.
//!
//! Output buffer layout (little-endian):
//!   [0..8]    u64 processed   — candidates tested (== count unless the
//!                               record area filled up first)
//!   [8..12]   u32 matches     — number of 60-byte records that follow
//!   [12..]    records: u64 counter | 32-byte passphrase (zero-padded) |
//!                      20-byte HASH160
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

/// Passphrases are at most 32 characters (62^32 dwarfs the u64 counter).
const MAX_PASS_LEN: usize = 32;
/// A mainnet P2PKH address is at most 34 base58 characters.
const MAX_ADDR_LEN: usize = 34;
/// counter (8) + passphrase (32) + HASH160 (20).
const RECORD_LEN: usize = 60;
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

/// Base58Check of version 0x00 + HASH160 (mainnet P2PKH), written into a
/// fixed 34-byte buffer. Returns the encoded length.
fn base58check_p2pkh(hash160: &[u8; 20]) -> ([u8; MAX_ADDR_LEN], usize) {
    let mut payload = [0u8; 25];
    payload[1..21].copy_from_slice(hash160);
    let checksum = sha256(&sha256(&payload[..21]));
    payload[21..25].copy_from_slice(&checksum[..4]);

    let zeros = payload.iter().take_while(|&&b| b == 0).count();
    // Repeated carry propagation, base 256 -> base 58 (digits little-endian).
    let mut digits = [0u8; MAX_ADDR_LEN];
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

/// Grinds counters `[start, start + count)`: counter -> base-62 passphrase of
/// `pass_len` chars -> SHA-256 private key -> compressed pubkey -> HASH160 ->
/// P2PKH address, recording candidates whose address starts with `prefix`.
///
/// # Safety
/// `prefix`/`prefix_len` must be readable and `out` must hold `out_cap`
/// writable bytes (>= `HEADER_LEN` + 60 per record capacity desired).
#[no_mangle]
pub unsafe extern "C" fn vanity_grind(
    prefix: *const u8,
    prefix_len: usize,
    pass_len: usize,
    start: u64,
    count: u64,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if prefix.is_null() || out.is_null() || prefix_len == 0 || prefix_len > MAX_ADDR_LEN
        || pass_len == 0 || pass_len > MAX_PASS_LEN || out_cap < HEADER_LEN
    {
        return -1;
    }
    let prefix = std::slice::from_raw_parts(prefix, prefix_len);
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
        let seckey = sha256(&pass[..pass_len]);
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
                let hash160: [u8; 20] = Ripemd160::digest(sha256(&serialized)).into();
                let (addr, addr_len) = base58check_p2pkh(&hash160);
                if addr_len >= prefix_len && &addr[..prefix_len] == prefix {
                    if (matches as usize) < record_cap {
                        let at = HEADER_LEN + matches as usize * RECORD_LEN;
                        out_slice[at..at + 8].copy_from_slice(&(start + processed).to_le_bytes());
                        out_slice[at + 8..at + 8 + MAX_PASS_LEN].fill(0);
                        out_slice[at + 8..at + 8 + pass_len].copy_from_slice(&pass[..pass_len]);
                        out_slice[at + 40..at + 60].copy_from_slice(&hash160);
                        matches += 1;
                    } else {
                        status = -2;
                        break;
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
