# AGENTS.md

Guidelines for AI coding agents.

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before making changes. The short
  version: never generate entropy used for key material, no network egress, output stays a single
  self-contained `entropylab.html`.
- **Read before acting:** read a file before editing or overwriting it — edit
  what is actually on disk, not what you assume.
- **Never assume:** when something is unknown, check the documentation or the
  code first, then proceed.
- Edit sources in `src/` (and the Rust crates in `secp256k1-wasm/` and
  `vanity-wasm/`), never generated build artifacts — that includes
  `entropylab.html`, `src/js/secp256k1-wasm-b64.js`, and
  `src/js/vanity-wasm-b64.js` (regenerate the WASM modules with
  `npm run build:wasm`; it needs Rust, toolchains pinned by each crate's
  `rust-toolchain.toml`).
- Make the smallest change that works. No refactors, reformatting, or new
  dependencies.
- Don't weaken or skip tests. New behaviour needs a test.
- Before finishing, run `npm run build && npm test` and make sure they pass.
