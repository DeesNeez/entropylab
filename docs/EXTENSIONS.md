# EntropyLab extensions

EntropyLab can load third-party extensions: JavaScript files that make a
documented, versioned `EntropyLab` API available to features that are not
part of the application itself. Extensions are supported by every workspace,
loaded locally, and evaluated while the page runs offline.

## Security model — read this first

An extension is **arbitrary JavaScript running with the same privileges as
EntropyLab itself**. There is no sandbox between an extension and the
application: anything a malicious extension can see (seed phrases, private
keys, PSBT contents) it can also exfiltrate if the machine somehow becomes
online again, or simply misuse while the page is open.

The declared **hooks** in the manifest (`entropy`, `wallets`, `ui` — see
below) are a public review aid, not a permission gate: every loaded
extension can call every hook. The loader lists them so reviewers can see
the intended surface at a glance.

Therefore:

- Load only extension code you have personally read or had audited.
- Extension authors should publish the SHA-256 checksum of their file. The
  Extensions workspace shows the SHA-256 of every loaded extension; compare
  it against the published value before trusting it with wallet material.
- Loaded extensions are persistent for the page session only. Reload
  EntropyLab to wipe extension state along with everything else.

The maintainers do not audit individual extensions. Treat extension code
with the same suspicion you would treat a modified copy of \(index.html\)
itself.

## The extension file format

An extension is a single JavaScript file (or pasted source) that calls
`EntropyLab.registerExtension(manifest)` when it is evaluated. Everything
runs under the standard EntropyLab content-security policy, so a source file
never needs remote resources.

### Manifest

`registerExtension` accepts one manifest object:

| Field          | Type     | Required | Constraints |
| -------------- | -------- | -------- | ----------- |
| `id`           | string   | yes      | 1–64 lowercase letters/digits/hyphens, first char a letter or digit. Must be unique across loaded extensions. |
| `name`         | string   | yes      | 1–80 characters. |
| `version`      | string   | yes      | Semantic version, e.g. `"1.0.0"`. |
| `author`       | string   | no       | At most 80 characters. |
| `description`  | string   | no       | At most 600 characters. |
| `activate`     | function | no       | Called once with the extension API object. |
| `hooks`        | object   | no       | Declared hooks. Up to three optional names — `entropy`, `wallets`, `ui` — each a short string describing the intended use. |

`registerExtension` throws a descriptive `Error` when the manifest is
invalid or the `id` is already taken. It returns a frozen public record:
`{ id, name, version, author, description, hooks, status, error, digest, loadedAt }`.

`status` is `"registered"`, `"active"`, or `"failed"` (when `activate`
threw — the message is in `error`).

The frozen manifest helpers are also available:

- `EntropyLab.validateManifest(manifest)` — throws on invalid input,
  returns a normalized frozen copy otherwise.
- `EntropyLab.listExtensions()` — frozen copies of all loaded records.
- `EntropyLab.unregisterExtension(id)` — removes the record and any panels
  the extension created.

## The extension API

The `activate(manifest)` function receives an API object containing the
whole public API surface; the same fields are also reachable on the
`EntropyLab` global itself:

```js
{
  formatVersion: 1,
  helpers: { escape(text) },
  entropy: { get, set },
  wallets: { active, watch },
  ui: { openWorkspace },
  addPanel({ title, render }),
}
```

Where a hook is capable of failing because the app isn't in a browser
(it only exists when `window.hodlAppState` is present), it throws a
documented message. In Node test runs without a DOM, `ui.openWorkspace`
and watching wallets are a no-op and entropy getters return `null`.

### Entropy hook

Per-mode entropy inputs of the **active key**, not just-pasted values.

- `api.entropy.get(mode)` — returns the current per-mode input.
- `api.entropy.set(mode, value)` — writes to the input and, when the
  matching mode is visible in the browser, into the DOM field so the app
  state and the UI stay in sync.

Supported `mode` ids, where each maps to the element the app uses:

| mode    | element | purpose |
| ------- | ------- | ------- |
| `dice`  | `#dice` | Dice rolls or D+ dice (switch follows `state.diceMethod`). |
| `cards` | `#cards` | Playing-card transcript input. |
| `hex`   | `state.fields[state.entropyFormat]` | Number bases; one of `bin` / `base4` / `base8` / `base32` / `base64` / `hex` depending on the selected format. |
| `seed`  | `#seed` | BIP39 seed phrase surface. |
| `key`   | `#key` | Private key / WIF / mini-key surface. |

`get`/`set` throws a descriptive `Error` for an unrecognized mode.

### Wallets hook

A read-only, frozen snapshot of the **active key's computed result**.
Snapshots are deliberately flat, frozen objects so watchers always see the
same schema and can't accidentally alias live app state.

- `api.wallets.active` — `.get` accessor on the API object; the current
  snapshot or `null` when no key has been computed.
- `api.wallets.watch(listener)` — subscribe to wallet changes. The
  listener fires with the new snapshot whenever it differs from the
  previous one. Returns an unsubscribe function. A throwing listener's
  error propagates out of the polling tick.

Snapshot shapes, by `kind`:

- **hd**: `kind, network, mnemonic, passphraseUsed, entropyHex, seedHex, rootXprv, rootXpub, masterFingerprint, parentFingerprint, nodeFingerprint, imported, importedPrivateKey, importedPublicKey, multisigCosignerExports[], accounts[], notes[], warnings[]`
- **single**: `kind, network, privHex, wifCompressed, wifUncompressed, pubkeyCompressed, pubkeyUncompressed, p2pkhUncompressed, p2pkhCompressed, p2shP2wpkh, p2wpkh, p2tr, minikey, notes[], warnings[]`
- **msig**: `kind, network, m, n, script, scriptStandard, account, accountMixed, xpubs[], receiveDescriptor, changeDescriptor, walletDescriptor, receive[], change[], notes[], warnings[]`

Any unexpected `kind` still gets a `kind, network, notes[], warnings[]`
base snapshot. `accounts[]` entries are the derivation result objects the
app itself uses; the extension API deliberately defers to that.

### UI hook

- `api.ui.openWorkspace(id)` — programmatically switches the workspace
  between `calc` (Key Derivation), `msig` (Multi Signature), `psbt`,
  and `ext` (Extensions); clicks the target tab. Throws on unknown ids.

## Panels (the render hook)

`api.addPanel({ title, render })` creates a card inside the Extensions
workspace:

- `title` — shown as the panel heading.
- `render(context)` — returns an HTML string. `context` contains
  `{ helpers, manifest }`.

The return value of `addPanel` has:

- `title`
- `element` — the panel's `<section>` DOM node.
- `update()` — re-runs `render` and replaces the panel body.

Anything a render returns other than a string throws. Panel markup is
injected as HTML — use `helpers.escape` for user-controlled values.

### `helpers.escape(value)`

Escapes `&`, `<`, `>`, `"`, `'`. Use this when interpolating any string the
user (or the network) could influence.

## Example

Below, a real extension: panel + entropy & wallet hooks.

```js
EntropyLab.registerExtension({
  id: "watch-summary",
  hooks: {
    entropy: "read per-mode entropy inputs",
    wallets: "watch results",
    ui: "jump to Key Derivation",
  },
  name: "Watch summary",
  version: "1.0.0",
  author: "you",
  description: "Echoes the active key's entropy and watches wallet results.",
  activate(api) {
    let lastMode = null;
    let lastAddress = "(no wallet yet)";
    const unsubscribe = api.wallets.watch((snapshot) => {
      if (snapshot?.accounts?.length > 0 && snapshot.accounts[0].receive?.length > 0) {
        lastAddress = snapshot.accounts[0].receive[0].address;
      } else if (snapshot?.kind === "single") {
        lastAddress = snapshot.p2wpkh ?? "(n/a)";
      }
    });

    const panel = api.addPanel({
      title: "Watch summary",
      render({ helpers }) {
        return `<p>First address: ${helpers.escape(lastAddress)}</p>
                <p>Dice input: ${helpers.escape(api.entropy.get("dice")) ?? "(dice)"}</p>`;
      },
    });
    api.ui.openWorkspace("ext");
    // unsubscribe(); + api.ui.openWorkspace("calc"); onremove
  },
});
```

## Loading versions and compatibility

`EntropyLab.version` exposes the running application version (e.g.
`"v0.1.3"`). Extensions that depend on internals they can reach via the API
should treat that value as advisory; the contract is `formatVersion`.

## Where to load extensions

Open the **Extensions** workspace (the fourth tab, next to
Key Derivation / Multi Signature / PSBT). Either pick a local `.js` file or
paste the source, then check the SHA-256 in the list under the loader.
