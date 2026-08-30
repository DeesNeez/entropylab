// Builds the vanity-grinder WASM artifact from the pinned Rust sources in
// vanity-wasm/ and writes it as a committed, importable JS module:
// src/js/vanity-wasm-b64.js (base64 + sha256 of the wasm bytes).
//
// Same flow as scripts/build-wasm.mjs: the generated module is committed so
// `npm run build` keeps working with Node alone, and CI rebuilds it from the
// pinned Rust sources (vanity-wasm/rust-toolchain.toml, Cargo.lock) and runs
// the vanity test suite against the fresh build. Build-host paths are
// remapped so the binary does not carry the builder's home directory.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const crateDir = join(root, "vanity-wasm");
const wasmPath = join(crateDir, "target/wasm32-unknown-unknown/release/vanity_wasm.wasm");
const outPath = join(root, "src/js/vanity-wasm-b64.js");

// Without a remap, rustc bakes the builder's absolute paths (e.g.
// /home/<user>/.cargo/...) into panicking code of registry sources, which
// both fingerprints the build host and breaks cross-machine comparisons.
const home = process.env.HOME ?? "";
const rustflags = [
  `--remap-path-prefix=${home}/.cargo/=cargo/`,
  `--remap-path-prefix=${home}/.rustup/=rustup/`,
].join(" ");

execFileSync(
  "cargo",
  ["build", "--locked", "--release", "--target", "wasm32-unknown-unknown"],
  { cwd: crateDir, stdio: "inherit", env: { ...process.env, RUSTFLAGS: rustflags } }
);

const wasm = readFileSync(wasmPath);
const sha256 = createHash("sha256").update(wasm).digest("hex");
const b64 = wasm.toString("base64");

const out = `// GENERATED FILE - do not edit. Rebuild with \`npm run build:wasm\`.
// libsecp256k1 0.8.0 (vendored by secp256k1-sys 0.14.0, see
// vanity-wasm/Cargo.lock) plus sha2 0.10.9 / ripemd 0.1.3, compiled to
// WebAssembly from vanity-wasm/ with the pinned Rust 1.95.0 toolchain.
// wasm sha256: ${sha256}
export const VANITY_WASM_B64 =
  "${b64}";
`;

writeFileSync(outPath, out);
console.log(`Built vanity WASM artifact`);
console.log(`  ${wasm.length} bytes wasm, sha256 ${sha256}`);
console.log(`  wrote ${outPath} (${Buffer.byteLength(out, "utf8")} bytes)`);
