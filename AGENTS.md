# EntropyLab — agent-facing context

Read this file before making changes in this repository. It records the
project's conventions that matter for an agent (build/test/CI behavior,
the extension interface archive, and the doc/code areas that must stay in
sync). For project background and features, see `README.md`.

## Do once per session

Run `npm run ci` before delivering. CI is `npm run test:ci` + `npm run
build` + `npm run verify` — exactly the same steps CI runs.

- `npm run build` inlines `src/index.html` and the `src/js/*` modules into
  the committed `index.html` / `entropylab-<version>.html` at the repo
  root. The version is read from `package.json`.
- `npm run verify` checks the build output, manifest, and assets.
- `npm test` additionally runs the headless-Firefox browser suite
  (`test/browser.test.mjs`). On an offline/CI machine without Firefox it
  will be skipped by timing out — the CI subset is enough for local work.

## Extension interface (src/js/extensions.js)

Anything you change here must also be reflected in `docs/EXTENSIONS.md`
and, where relevant, in the API tests (`test/extensions.test.mjs`).

Key conventions:

- `EntropyLab` is the public, frozen global. Extensions interact **only**
  with this object — never with `window` internals directly.
- Manifest hooks (`hooks: { entropy, wallets, ui }`) are declared as
  strings; validation validates names but not the values.
- The **wallet snapshot mapper** (`entWalletSnapshot` in
  `src/js/extensions.js`) is the single stable shape across all app
  wallet kinds (`hd`, `single`, `msig`). If `src/js/app.js` reshapes its
  `result` anywhere, update that mapper in the same change to keep the
  extension-facing shape stable. A drift leads to silently broken
  extensions instead of safe errors.
- The accessor `globalThis.hodlAppState` is exposed from the bottom of
  `src/js/app.js` for the extension interface; don't expand that surface
  without a review.
- App and extension tests must hold specific literal shapes. The test file
  uses lowercase-hex-only digests — normalize before asserting.

## Build tokens

`src/index.html` is a template with build tokens. Every `/*@@JS_*@@*/`
token must be resolved in `scripts/build.mjs`. The build also injects
`{{VERSION}}` from `package.json`. Don't introduce a new `.js` src module
without registering its build token in both the template and build
script — otherwise the build throws on "Unreplaced build token".

## Tests

- `test:ci` is the list of node-side suites (source invariants, descriptor,
  cards, PSBT features, extensions). CI runs it along with build+verify.
- The browser suite (`test:browser`) exercises against assembled HTML. On
  systems without Firefox it is expected to fail or time out; CI skips it.
- Re-run `npm run build` after touching src — the committed root files
  (`index.html`, `entropylab-<version>.html`, `versions.json`) derive from
  it.

## Documentation to keep in sync

When you move anything public:

- API surface → `docs/EXTENSIONS.md`
- Behavioral/security → `SECURITY.md` when touched
- Project-wide user-facing info → `README.md`
- Agent conventions (this file) → `AGENTS.md`
