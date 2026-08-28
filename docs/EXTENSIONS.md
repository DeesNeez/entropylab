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

`registerExtension` throws a descriptive `Error` when the manifest is
invalid or the `id` is already taken. It returns a frozen public record:
`{ id, name, version, author, description, status, error, digest, loadedAt }`.

`status` is `"registered"`, `"active"`, or `"failed"` (when `activate`
threw — the message is in `error`).

The frozen manifest helpers are also available:

- `EntropyLab.validateManifest(manifest)` — throws on invalid input,
  returns a normalized frozen copy otherwise.
- `EntropyLab.listExtensions()` — frozen copies of all loaded records.
- `EntropyLab.unregisterExtension(id)` — removes the record and any panels
  the extension created.

### The extension API

The `activate(manifest)` function receives an API object:

```js
{
  formatVersion: 1,          // ENTROPYLAB extension API version
  helpers: { escape(text) }, // HTML-escaping helper, same as the app uses
  addPanel({ title, render })
}
```

`formatVersion` is `1`. EntropyLab will bump the extension API version only
when the contract changes incompatibly.

`helpers.escape(value)` escapes a string for interpolation into HTML, the
same helper the application uses internally. Panel rendering is deliberately
primitive — the extension returns an HTML string, the loader injects it.
Prefer text content and `helpers.escape` over building event-attaching
markup from untrusted values.

### Panels (the current hook type)

`api.addPanel({ title, render })` creates a card inside the Extensions
workspace:

- `title` — shown as the panel heading.
- `render(context)` — returns an HTML string. `context` contains
  `{ helpers, manifest }`.

The return value of `addPanel` has:

- `title`
- `element` — the panel's `<section>` DOM node (for attaching event handlers
  and further DOM updates).
- `update()` — re-runs `render` and replaces the panel body with the new
  result.

An extension can create any number of panels. Panels created by an extension
are removed from the DOM when the extension is unregistered.

## Example

Save this as `echo.js`, load it, and get a panel that echoes whatever you
type — escaped — into a paragraph. It demonstrates the manifest, escaped
rendering, DOM attachment through `panel.element`, and panel updates.

```js
EntropyLab.registerExtension({
  id: "echo-demo",
  name: "Echo demo",
  version: "1.0.0",
  author: "you",
  description: "Echoes text, escaped, to demonstrate the extension format.",
  activate(api) {
    let last = "(nothing yet)";
    const panel = api.addPanel({
      title: "Echo",
      render({ helpers }) {
        return `<input type="text" placeholder="type here" aria-label="Echo input">
                <p class="echo-out">${helpers.escape(last)}</p>`;
      },
    });
    panel.element.querySelector("input").addEventListener("input", (event) => {
      last = event.target.value;
      panel.update();
    });
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
