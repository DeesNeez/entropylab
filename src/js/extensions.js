// EntropyLab extension interface.
//
// Defines the documented `EntropyLab` global that third-party extensions use
// to register themselves, builds the Extensions workspace (loader + registry
// listing + extension panels), and wires that workspace into the existing
// workspace switcher without touching the application internals.
//
// In addition to panels (formatVersion 1), extensions may declare focused
// data hooks on their manifest:
//   - `entropy`      set/get user entropy inputs (per derivation mode)
//   - `wallets`      read/watch wallet derivation results state.result → public snapshot)
//   - `ui`           open workspaces / open panels
//
// Wire drift note: wallet snapshots are built by a single stable mapper
// (entWalletSnapshot) — if a future app.js reshapes `result`, this one
// function must be updated so snapshot shapes stay stable for extensions.
//
// Security model (documented in docs/EXTENSIONS.md): an extension is
// arbitrary JavaScript executed with the same privileges as EntropyLab
// itself. There is no sandbox. Extensions must be audited and trusted like
// the application; the loader displays the SHA-256 of every source so users
// can compare it against the checksum published by the extension author.
const EntropyLabExtensionID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const EntropyLabExtensionVersion = /^\d+\.\d+\.\d+$/;
const ENTROPYLAB_EXTENSION_FORMAT = 1;

// The app determines the snapshot mapping below is built against. If app.js
// moves the result schema around, drift must be resolved by updating the
// mapper while keeping the shape.
const entRecords = [];
const entHelpers = Object.freeze({
  escape(value) {
    const entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return Array.from(String(value ?? ""), (c) => entities[c] ?? c).join("");
  },
});

// Snapshot helpers used by loadSource to attribute records created while a
// source file is evaluated.
let entPendingDigest = null;

// Evaluates extension source. Calls to registerExtension() made while the
// source runs are attributed to this source's digest.
//
// In a browser the source is injected as an inline <script> element: the
// application's CSP allows `script-src 'unsafe-inline'` but deliberately not
// `unsafe-eval`, so eval() and new Function() would be blocked. Inline
// <script> elements execute synchronously on insertion, which keeps digest
// attribution for registerExtension() calls. The new Function() fallback
// only applies to headless test runs, where document is undefined.
async function entLoad(source) {
  if (typeof source !== "string" || !source.trim()) {
    throw new Error("Extension source is empty.");
  }
  entPendingDigest = await entSha256Hex(source);
  try {
    if (typeof document !== "undefined") {
      const script = document.createElement("script");
      // textContent assignment is parsed as a text node (not HTML), so
      // closing tags inside the source cannot escape.
      script.textContent = source;
      document.body.appendChild(script);
      script.remove();
      return undefined;
    }
    return new Function("EntropyLab", source)(EntropyLab);
  } finally {
    entPendingDigest = null;
  }
}

function entPublicRecord(record) {
  const { id, name, version, author, description, hooks = undefined } = record.manifest;
  return Object.freeze({
    id,
    name,
    version,
    author,
    description,
    hooks,
    status: record.status,
    error: record.error,
    digest: record.digest,
    loadedAt: record.loadedAt,
  });
}

function entNormalizeManifest(manifest) {
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("Extension manifest must be an object.");
  }
  const { id, name, version, author, description, activate, hooks } = manifest;
  if (typeof id !== "string" || !EntropyLabExtensionID.test(id)) {
    throw new Error(
      "Extension id must be 1-64 lowercase characters: letters, digits, and hyphens (starting with a letter or digit).",
    );
  }
  if (typeof name !== "string" || !name.trim() || name.length > 80) {
    throw new Error("Extension name must be a non-empty string of at most 80 characters.");
  }
  if (typeof version !== "string" || !EntropyLabExtensionVersion.test(version)) {
    throw new Error("Extension version must be a semantic version string like \"1.0.0\".");
  }
  if (author !== undefined && (typeof author !== "string" || author.length > 80)) {
    throw new Error("Extension author must be a string of at most 80 characters.");
  }
  if (description !== undefined && (typeof description !== "string" || description.length > 600)) {
    throw new Error("Extension description must be a string of at most 600 characters.");
  }
  if (activate !== undefined && typeof activate !== "function") {
    throw new Error("Extension activate must be a function.");
  }
  if (hooks !== undefined) {
    if (hooks === null || typeof hooks !== "object" || Array.isArray(hooks)) {
      throw new Error("Extension hooks must be an object when provided.");
    }
    const allowed = { entropy: "set|get", wallets: "watch", ui: "workspace" };
    for (const key of Object.keys(hooks)) {
      if (!Object.hasOwn(allowed, key)) {
        throw new Error(
          `Extension hook "${key}" is not supported. Supported hooks: ${Object.keys(allowed).join(", ")}.`,
        );
      }
      if (typeof hooks[key] !== "string" || hooks[key].length > 120) {
        throw new Error(`Extension hook "${key}" must be a short descriptive string.`);
      }
    }
  }
  return Object.freeze({
    id,
    name: name.trim(),
    version,
    author: author ?? null,
    description: description ?? null,
    activate: activate ?? null,
    hooks: hooks ? Object.freeze({ ...hooks }) : null,
  });
}

// --- Wallet snapshot mapper. One stable target across all wallet kinds. ---

// Copies a shallow row array without leaking live references.
function entRows(rows) {
  return Array.isArray(rows) ? rows.map((row) => ({ ...row })) : [];
}

// A normalized, frozen snapshot of a derivation result. The shape is the
// doc-supported global contract across "hd", "single", and "msig" kinds,
// even though the app stores slightly different fields per kind.
function entWalletSnapshot(result) {
  if (result === null || typeof result !== "object") return null;
  const { kind, network, notes = [], warnings = [] } = result;
  if (!kind) return null;
  const base = { kind, network, notes: entRows(notes), warnings: entRows(warnings) };
  if (kind === "hd") {
    return Object.freeze({
      ...base,
      mnemonic: result.mnemonic ?? null,
      passphraseUsed: !!result.passphraseUsed,
      entropyHex: result.entropyHex ?? null,
      seedHex: result.seedHex ?? null,
      rootXprv: result.rootXprv ?? null,
      rootXpub: result.rootXpub ?? null,
      masterFingerprint: result.masterFingerprint ?? null,
      parentFingerprint: result.parentFingerprint ?? null,
      nodeFingerprint: result.nodeFingerprint ?? null,
      imported: !!result.imported,
      importedPrivateKey: result.importedPrivateKey ?? null,
      importedPublicKey: result.importedPublicKey ?? null,
      multisigCosignerExports: entRows(result.multisigCosignerExports),
      accounts: entRows(result.accounts),
    });
  }
  if (kind === "single") {
    return Object.freeze({
      ...base,
      privHex: result.privHex ?? null,
      wifCompressed: result.wifCompressed ?? null,
      wifUncompressed: result.wifUncompressed ?? null,
      pubkeyCompressed: result.pubkeyCompressed ?? null,
      pubkeyUncompressed: result.pubkeyUncompressed ?? null,
      p2pkhUncompressed: result.p2pkhUncompressed ?? null,
      p2pkhCompressed: result.p2pkhCompressed ?? null,
      p2shP2wpkh: result.p2shP2wpkh ?? null,
      p2wpkh: result.p2wpkh ?? null,
      p2tr: result.p2tr ?? null,
      minikey: result.minikey ?? null,
    });
  }
  if (kind === "msig") {
    return Object.freeze({
      ...base,
      m: result.m ?? null,
      n: result.n ?? null,
      script: result.script ?? null,
      scriptStandard: result.scriptStandard ?? null,
      account: result.account ?? null,
      accountMixed: !!result.accountMixed,
      xpubs: entRows(result.xpubs),
      receiveDescriptor: result.receiveDescriptor ?? null,
      changeDescriptor: result.changeDescriptor ?? null,
      walletDescriptor: result.walletDescriptor ?? null,
      receive: entRows(result.receive),
      change: entRows(result.change),
    });
  }
  // Unknown kinds still snapshot the common base fields.
  return Object.freeze(base);
}

// --- Derivation-mode entropy hooks ---

// Maps the app's mode ids to the fields in a key's per-mode form cache.
// App modes: dice/cards/hex(number bases)/seed/key. Dice uses
// "dice"/"dplusDice"; hex picks the base-format field; the passphrase is
// shared.
const ENT_MODE_PATHS = Object.freeze({
  dice: ["fields", "dice", "dplusDice"],
  cards: ["fields", "cards"],
  // hex picked dynamically below via entropyFormat
  hex: ["fields"],
  seed: ["fields", "seed"],
  key: ["fields", "key"],
});

function entGetKeyState() {
  if (typeof window === "undefined") return null;
  const state = window.hodlAppState;
  if (!state) return null;
  return state.activeKey ?? null;
}

// Reads the entropy hook for the active key. `fieldIndex` picks between the
// dice-equivalent fields for dice (regular vs dplus).
function entEntropyGet(mode) {
  const state = entGetKeyState();
  if (!state || !Object.hasOwn(ENT_MODE_PATHS, mode)) return null;
  if (mode === "dice") {
    const isDplus = state.diceMethod === "dplus";
    return state.fields[isDplus ? "dplusDice" : "dice"];
  }
  if (mode === "hex") {
    const format = state.entropyFormat;
    return state.fields ? state.fields[format] : null;
  }
  return state.fields ? state.fields[ENT_MODE_PATHS[mode][1]] : null;
}

// Writes to the mode-specific entropy field. Also updates the matching DOM
// input when the mode is currently the visible tab in a browser.
function entEntropySet(mode, value) {
  const state = entGetKeyState();
  if (!state || !Object.hasOwn(ENT_MODE_PATHS, mode)) {
    throw new Error(`Entropy hook "${mode}" is not available.`);
  }
  const text = String(value ?? "");
  if (mode === "dice") {
    const isDplus = state.diceMethod === "dplus";
    state.fields[isDplus ? "dplusDice" : "dice"] = text;
  } else if (mode === "hex") {
    state.fields[state.entropyFormat] = text;
  } else {
    state.fields[ENT_MODE_PATHS[mode][1]] = text;
  }
  const elementId = {
    dice: "dice",
    cards: "cards",
    hex: state.entropyFormat,
    seed: "seed",
    key: "key",
  }[mode];
  if (elementId && typeof document !== "undefined") {
    const element = document.getElementById(elementId);
    if (element) element.value = text;
  }
  return true;
}

// --- The exposed API object ---

const EntropyLab = {
  formatVersion: ENTROPYLAB_EXTENSION_FORMAT,
  get version() {
    if (typeof document === "undefined") return null;
    return document.querySelector('meta[name="application-version"]')?.content ?? null;
  },

  validateManifest: entNormalizeManifest,

  // Evaluates extension source text. Calls to registerExtension() made while
  // the source runs are attributed to this source's SHA-256 digest.
  loadSource: entLoad,

  // Entropy hook (per-mode): set/get user-supplied entropy for the active key.
  entropy: {
    get: entEntropyGet,
    set: entEntropySet,
  },

  // Wallet hook: a frozen snapshot of the active key's computed result, plus
  // a change notifier that avoids console-only errors.
  wallets: {
    get active() {
      const state = entGetKeyState();
      return state ? entWalletSnapshot(state.result) : null;
    },
    // Subscribe to wallet changes: invokes listener with the new snapshot
    // whenever `wallets.active` produced a meaningfully different value.
    // Returns an unsubscribe function. A throwing listener propagates its
    // error on the polling tick where it happened.
    watch(listener) {
      if (typeof listener !== "function") {
        throw new Error("wallets.watch(listener) needs a function.");
      }
      if (typeof window === "undefined") return () => {};
      let lastJson = entGetKeyState() ? JSON.stringify(entWalletSnapshot(entGetKeyState().result)) : "null";
      const poll = () => {
        const state = entGetKeyState();
        const snapshot = state ? entWalletSnapshot(state.result) : null;
        const json = JSON.stringify(snapshot);
        if (json !== lastJson) {
          lastJson = json;
          listener(snapshot);
        }
      };
      const timer = window.setInterval(poll, 500);
      return () => window.clearInterval(timer);
    },
  },

  // UI hook: jump to a workspace ("calc" / "msig" / "psbt" / "ext").
  ui: {
    openWorkspace(id) {
      const allowed = ["calc", "msig", "psbt", "ext"];
      if (!allowed.includes(id)) {
        throw new Error(`UI workspace "${id}" is not openable. Allowed: ${allowed.join(", ")}.`);
      }
      if (typeof document === "undefined") throw new Error("UI hooks need a browser.");
      const workspace = document.getElementById("workspace");
      if (!workspace) throw new Error("Workspace switcher is not present.");
      const target = [...workspace.children].find(
        (button) => button instanceof Element && button.dataset?.workspace === id,
      );
      if (!target) throw new Error(`Workspace "${id}" is not present.`);
      target.click();
      return true;
    },
  },

  registerExtension(manifest) {
    const normalized = entNormalizeManifest(manifest);
    if (entRecords.some((record) => record.manifest.id === normalized.id)) {
      throw new Error(`An extension with id "${normalized.id}" is already loaded.`);
    }
    const record = {
      manifest: normalized,
      digest: entPendingDigest ? entPendingDigest : null,
      status: "registered",
      error: null,
      loadedAt: new Date().toISOString(),
      panels: [],
    };
    entRecords.push(record);
    if (normalized.activate) {
      try {
        normalized.activate(entApiFor(record));
        record.status = "active";
      } catch (error) {
        record.status = "failed";
        record.error = String(error && error.message ? error.message : error);
      }
    }
    entRenderList();
    return entPublicRecord(record);
  },

  unregisterExtension(id) {
    const index = entRecords.findIndex((record) => record.manifest.id === String(id));
    if (index < 0) throw new Error(`No extension with id "${id}" is loaded.`);
    const [record] = entRecords.splice(index, 1);
    for (const panel of record.panels) {
      panel.element?.remove();
    }
    entRenderList();
    return true;
  },

  listExtensions() {
    return entRecords.map(entPublicRecord);
  },
};

// The API handed to an extension's activate() function. Exposed hooks:
// `api.entropy`, `api.wallets`, `api.ui` — same API surface as EntropyLab,
// just the per-extension activate-oriented view.
function entApiFor(record) {
  return Object.freeze({
    formatVersion: ENTROPYLAB_EXTENSION_FORMAT,
    helpers: entHelpers,
    entropy: EntropyLab.entropy,
    wallets: EntropyLab.wallets,
    ui: EntropyLab.ui,
    addPanel({ title, render }) {
      if (typeof title !== "string" || !title.trim()) {
        throw new Error("Panel title must be a non-empty string.");
      }
      if (typeof render !== "function") {
        throw new Error("Panel render must be a function returning an HTML string.");
      }
      const panel = { title: title.trim(), render, element: null, manifest: record.manifest };
      record.panels.push(panel);
      if (typeof document !== "undefined") entMountPanel(panel, record);
      return Object.freeze({
        title: panel.title,
        get element() {
          return panel.element;
        },
        update() {
          entRenderPanel(panel, record);
        },
      });
    },
  });
}

// --- DOM integration. Everything below is a no-op in Node test runs. ---

const ENT_HAS_DOM = typeof document !== "undefined" && typeof window !== "undefined";

function entMountPanel(panel, record) {
  const host = document.getElementById("ext-panels");
  if (!host) return;
  const section = document.createElement("section");
  section.className = "card ext-panel";
  const heading = document.createElement("h3");
  heading.textContent = panel.title;
  const body = document.createElement("div");
  body.className = "ext-panel-body";
  section.append(heading, body);
  panel.element = section;
  host.appendChild(section);
  entRenderPanel(panel, record);
}

function entRenderPanel(panel, record) {
  if (!panel.element) return;
  const body = panel.element.querySelector(".ext-panel-body");
  if (!body) return;
  try {
    const html = panel.render({ helpers: entHelpers, manifest: record.manifest });
    if (typeof html !== "string") throw new Error("Panel render must return an HTML string.");
    body.innerHTML = html;
  } catch (error) {
    body.textContent = `Panel failed to render: ${error && error.message ? error.message : error}`;
    body.classList.add("ext-error");
  }
}

function entRenderList() {
  if (!ENT_HAS_DOM) return;
  const host = document.getElementById("ext-list");
  if (!host) return;
  host.textContent = "";
  if (!entRecords.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "No extensions loaded.";
    host.appendChild(empty);
    return;
  }
  for (const record of entRecords) {
    const { id, name, version, author, description, hooks = undefined } = record.manifest;
    const item = document.createElement("div");
    item.className = "ext-item";
    const title = document.createElement("div");
    title.className = "ext-item-title";
    const strong = document.createElement("strong");
    strong.textContent = `${name} v${version}`;
    title.appendChild(strong);
    if (author) {
      const by = document.createElement("span");
      by.className = "muted";
      by.textContent = ` by ${author}`;
      title.appendChild(by);
    }
    const status = document.createElement("span");
    status.className = record.status === "failed" ? "ext-status bad" : "ext-status ok";
    status.textContent = record.status === "failed" ? "failed to activate" : "loaded";
    title.appendChild(status);
    item.appendChild(title);
    const meta = document.createElement("div");
    meta.className = "ext-item-meta muted";
    const bits = [
      `id: ${id}`,
      record.digest ? `sha256: ${record.digest}` : "sha256: unknown",
      `loaded: ${record.loadedAt}`,
    ];
    meta.textContent = bits.join(" · ");
    item.appendChild(meta);
    if (hooks && Object.keys(hooks).length) {
      const hookLine = document.createElement("div");
      hookLine.className = "ext-item-hooks muted";
      hookLine.textContent = `hooks: ${Object.entries(hooks)
        .map(([key, desc]) => `${key}(${desc})`)
        .join(", ")}`;
      item.appendChild(hookLine);
    }
    if (description) {
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent = description;
      item.appendChild(p);
    }
    if (record.error) {
      const err = document.createElement("p");
      err.className = "ext-error";
      err.textContent = record.error;
      item.appendChild(err);
    }
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "btn secondary ext-remove";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => EntropyLab.unregisterExtension(id));
    item.appendChild(remove);
    host.appendChild(item);
  }
}

function entSha256Hex(text) {
  return crypto.subtle
    .digest("SHA-256", new TextEncoder().encode(text))
    .then((buffer) =>
      Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join(""),
    );
}

function entSetStatusMessage(message, isError = false) {
  const status = document.getElementById("ext-loader-status");
  if (!status) return;
  status.textContent = message;
  status.classList.toggle("ext-error", isError);
}

function entBuildUi() {
  if (!ENT_HAS_DOM) return;
  const appRoot = document.getElementById("btc-calc");
  const workspaceBox = document.getElementById("workspace");
  if (!appRoot || !workspaceBox) return;

  const card = document.createElement("section");
  card.className = "card no-print";
  card.id = "ext-card";
  card.hidden = true;

  const heading = document.createElement("h2");
  heading.textContent = "Extensions";
  card.appendChild(heading);

  const warning = document.createElement("p");
  warning.className = "ext-warning";
  warning.textContent =
    "Extensions are third-party code with the same powers as EntropyLab itself, including access to any wallet secrets you enter. Review the manifest's declared hooks — entropy/wallets/ui attach along with panels. Load only code you have read and trust, and compare the SHA-256 shown after loading against the checksum published by the extension author.";
  card.appendChild(warning);

  const fileLabel = document.createElement("label");
  fileLabel.className = "field";
  fileLabel.textContent = "Extension file (.js) ";
  const fileInput = document.createElement("input");
  fileInput.id = "ext-file";
  fileInput.type = "file";
  fileInput.accept = ".js,text/javascript";
  fileLabel.appendChild(fileInput);
  card.appendChild(fileLabel);

  const loadFile = document.createElement("button");
  loadFile.type = "button";
  loadFile.className = "btn secondary";
  loadFile.textContent = "Load from file";
  loadFile.addEventListener("click", async () => {
    const file = fileInput.files && fileInput.files[0];
    if (!file) {
      entSetStatusMessage("Choose an extension file first.", true);
      return;
    }
    if (file.size > 512 * 1024) {
      entSetStatusMessage("Rejected: extension files are limited to 512 KB.", true);
      return;
    }
    try {
      const text = await file.text();
      await entLoad(text);
      entSetStatusMessage(
        "Loaded. Verify the SHA-256 in the list below against the author's published checksum.",
      );
    } catch (error) {
      entSetStatusMessage(`Failed to load: ${error && error.message ? error.message : error}`, true);
    }
  });

  const pasteLabel = document.createElement("label");
  pasteLabel.className = "field";
  pasteLabel.textContent = "Or paste extension source ";
  const pasteInput = document.createElement("textarea");
  pasteInput.id = "ext-paste";
  pasteInput.rows = 5;
  pasteInput.placeholder = 'EntropyLab.registerExtension({ id: "…", … activate(api) { … } })';
  pasteLabel.appendChild(pasteInput);
  card.appendChild(pasteLabel);

  const loadPaste = document.createElement("button");
  loadPaste.type = "button";
  loadPaste.className = "btn secondary";
  loadPaste.textContent = "Load from paste";
  loadPaste.addEventListener("click", async () => {
    try {
      await entLoad(pasteInput.value);
      entSetStatusMessage(
        "Loaded. Verify the SHA-256 in the list below against the author's published checksum.",
      );
    } catch (error) {
      entSetStatusMessage(`Failed to load: ${error && error.message ? error.message : error}`, true);
    }
  });

  const row = document.createElement("div");
  row.className = "row";
  row.append(loadFile, loadPaste);
  card.appendChild(row);

  const status = document.createElement("p");
  status.id = "ext-loader-status";
  status.setAttribute("aria-live", "polite");
  card.appendChild(status);

  const listWrap = document.createElement("div");
  listWrap.id = "ext-list";
  card.appendChild(listWrap);

  const panels = document.createElement("div");
  panels.id = "ext-panels";
  card.appendChild(panels);

  const button = document.createElement("button");
  button.type = "button";
  button.className = "tab";
  button.dataset.workspace = "ext";
  button.setAttribute("aria-pressed", "false");
  button.textContent = "Extensions";
  workspaceBox.appendChild(button);

  function setActive(target) {
    for (const tab of Array.from(workspaceBox.children)) {
      const active = tab === target;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-pressed", String(active));
    }
  }

  button.addEventListener("click", () => {
    for (const id of ["calc-card", "msig-card", "psbt-card"]) {
      const el = document.getElementById(id);
      if (el) el.hidden = true;
    }
    card.hidden = false;
    setActive(button);
  });

  workspaceBox.addEventListener(
    "click",
    (event) => {
      if (event.target instanceof Element && event.target.closest(".tab") !== button) {
        card.hidden = true;
      }
    },
    true,
  );

  const psbtCard = document.getElementById("psbt-card");
  if (psbtCard && psbtCard.parentNode) {
    psbtCard.parentNode.insertBefore(card, psbtCard.nextSibling);
  } else {
    appRoot.appendChild(card);
  }

  entRenderList();
}

if (ENT_HAS_DOM) {
  globalThis.EntropyLab = EntropyLab;
  entBuildUi();
} else if (typeof globalThis !== "undefined") {
  globalThis.EntropyLab = EntropyLab;
}
