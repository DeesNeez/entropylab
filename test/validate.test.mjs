// Source validation and security invariants for the EntropyLab repository.
// Run with `npm run test:validate` or `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const pkg = JSON.parse(read("package.json"));
const appVersion = pkg.version;
const appFile = "entropylab.html";

// entropylab.html is a CI-generated artifact, not a committed source. Tests
// that read it require a fresh local build.
const ensureBuild = () => {
  if (!existsSync(join(root, appFile))) {
    execFileSync(process.execPath, [join(root, "scripts/build.mjs")], { stdio: "inherit" });
  }
};

const requiredFiles = [
  "README.md",
  "LICENSE",
  "package.json",
  "package-lock.json",
  "robots.txt",
  "sitemap.xml",
  "llms.txt",
  "assets/favicon.png",
  "assets/entropylab_dark.png",
  "assets/entropylab_light.png",
  "assets/entropylab_banner.png",
  "assets/entropylab-social.png",
  "scripts/build.mjs",
  "scripts/verify-site.mjs",
  "test/validate.test.mjs",
  "test/browser.test.mjs",
  "test/browser-instrumentation.html",
  "test/browser-suite.html",
  "src/index.html",
  "src/assets/logo-dark.png",
  "src/assets/logo-light.png",
  "src/css/styles.css",
  "src/js/app.js",
  "src/js/online.js",
  "src/js/network-check.js",
  "src/js/browser-check.js",
  "src/js/enhanced-inputs.js",
  "src/js/repeat-inputs.js",
  "src/js/sqlite-writer.js",
  "src/js/wallet-export.js",
  "test/sqlite-writer.test.mjs",
  "test/wallet-export.test.mjs",
  "test/wallet-export-reference.mjs",
  "test/browser-check.test.mjs",
  "test/psbt-metadata.test.mjs",
  "test/secret-clear.test.mjs",
  ".github/workflows/ci-cd.yml",
];

for (const file of requiredFiles) {
  test(`${file} exists`, () => {
    const path = join(root, file);
    assert.ok(existsSync(path) && statSync(path).isFile(), `${file} is missing or not a file`);
  });
}

test("package.json declares a valid version and the expected scripts", () => {
  assert.match(appVersion, /^\d+(\.\d+)*$/, `invalid version: ${appVersion}`);
  for (const script of ["build", "clean", "test", "verify", "ci"]) {
    assert.equal(typeof pkg.scripts?.[script], "string", `package.json is missing the "${script}" script`);
  }
});

test("dependencies and build tooling are exactly locked", () => {
  assert.match(pkg.packageManager, /^npm@\d+\.\d+\.\d+$/);
  for (const [name, version] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
    assert.match(version, /^\d+\.\d+\.\d+$/, `${name} must use an exact version`);
  }
  const lock = JSON.parse(read("package-lock.json"));
  assert.equal(lock.lockfileVersion, 3);
  assert.deepEqual(lock.packages[""].dependencies, pkg.dependencies);
  assert.deepEqual(lock.packages[""].devDependencies, pkg.devDependencies);
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path || entry.link) continue;
    assert.match(entry.integrity ?? "", /^sha512-/, `${path} has no SHA-512 package integrity`);
  }
  assert.equal(existsSync(join(root, "src/js/vendor.js")), false, "opaque vendor bundle must not return");
});

test("Node scripts and test files parse", () => {
  const nodeFiles = [
    "scripts/build.mjs",
    "scripts/verify-site.mjs",
    ...readdirSync(join(root, "test")).filter((name) => name.endsWith(".mjs")).map((name) => `test/${name}`),
  ];
  for (const file of nodeFiles) {
    execFileSync(process.execPath, ["--check", join(root, file)], { stdio: "pipe" });
  }
});

const readmeVersion = read("README.md").match(/^Current version: \*\*v([^*]*)\*\*$/m)?.[1] ?? "";

test("README version agrees with package.json", () => {
  assert.equal(readmeVersion, appVersion, `package.json: ${appVersion}; README: ${readmeVersion}`);
});

test("no versioned snapshots linger at the repository root", () => {
  const snapshots = readdirSync(root).filter((name) => /^entropylab-\d+(?:\.\d+)*\.html$/.test(name));
  assert.deepEqual(snapshots, [], `unexpected versioned snapshots: ${snapshots.join(", ")}`);
});

test("GitHub Pages aliases the canonical app at the site root only during deployment", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  assert.equal(existsSync(join(root, "index.html")), false, "index.html should not be committed");
  assert.match(
    workflow,
    /^\s*cp entropylab\.html _site\/index\.html\s*$/m,
    "Pages staging must copy entropylab.html to its required index.html entry file",
  );
  assert.match(workflow, /^\s*branches: \[rock\]\s*$/m, "CI must run for pushes to the default branch");
  assert.match(
    workflow,
    /github\.ref == 'refs\/heads\/rock'/,
    "Pages deployment must be gated to the default branch",
  );
  assert.doesNotMatch(workflow, /refs\/heads\/main/, "workflow must not target the retired branch name");
});

test("the app never fetches, so the CSP forbids connections", () => {
  assert.match(read("src/index.html"), /connect-src 'none'/);
  // The secp256k1 WebAssembly module compiles inline; the CSP must allow it
  // (without 'wasm-unsafe-eval', Chrome/Safari refuse compilation).
  assert.match(read("src/index.html"), /script-src 'unsafe-inline' 'wasm-unsafe-eval'/);
  assert.doesNotMatch(read("src/js/online.js") + read("src/js/network-check.js") + read("src/js/browser-check.js"), /\bfetch\s*\(/);
});

test("the WASM boot chain has a failure path that kills the page", () => {
  const app = read("src/js/app.js");
  assert.match(
    app,
    /secp256k1Ready\.then\(hodlBoot\)\.catch\(/,
    "app boot must catch secp256k1Ready rejection instead of leaving a dead page",
  );
  assert.match(app, /hodlCurveFailure/, "the boot rejection must render the sanity-failure kill screen");
  assert.match(app, /<tr><td>secp256k1 WebAssembly module<\/td><td>Failed<\/td><\/tr>/);
});

test("third-party actions are immutable and deployment is test-gated", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  assert.doesNotMatch(workflow, /^\s*uses:\s*[^\s]+@(?![0-9a-f]{40}(?:\s|$))/m);
  assert.match(workflow, /^\s{2}test-ci:\n(?:.|\n)*?^\s{4}needs: \[build\]$/m);
  assert.match(workflow, /^\s{2}test-browser:\n(?:.|\n)*?^\s{4}needs: \[build\]$/m);
  // The WASM gate must rebuild the bindings from the Rust sources, test the
  // fresh build, and block both the artifact commit and the Pages deploy.
  assert.match(workflow, /^\s{2}build-wasm:\n(?:.|\n)*?npm run build:wasm\n/m);
  assert.match(workflow, /^\s{2}build-wasm:\n(?:.|\n)*?node --test test\/secp256k1-wasm\.test\.mjs/m);
  assert.match(workflow, /^\s{2}deploy:\n(?:.|\n)*?^\s{4}needs: \[build, verify, test-ci, test-browser, build-wasm\]$/m);
});

test("the intentional low-entropy recovery behavior is documented", () => {
  const security = read("SECURITY.md");
  assert.match(security, /low-entropy dice transcripts are accepted intentionally/i);
  assert.match(security, /card\s+transcripts instead fail closed/i);
  assert.match(security, /hashing a short input\s+does not make it secure/i);
});

const htmlFiles = [appFile];

ensureBuild();

for (const file of htmlFiles) {
  test(`${file} declares HTML5`, () => {
    assert.match(read(file), /^<!DOCTYPE html>/);
  });
  test(`${file} has a closing html element`, () => {
    assert.match(read(file), /<\/html>\s*$/);
  });
  test(`${file} includes the offline content security policy`, () => {
    assert.ok(read(file).includes("default-src 'none'"), `${file} is missing the offline CSP`);
  });
  test(`${file} contains application JavaScript`, () => {
    assert.ok(read(file).includes("<script>"), `${file} has no inline script`);
  });
  test(`${file} has no remote executable subresources`, () => {
    const html = read(file);
    assert.doesNotMatch(html, /<(script|iframe)[^>]+src=["' ]*https?:\/\//i);
    assert.doesNotMatch(html, /<link(?![^>]*rel="canonical")[^>]+href=["' ]*https?:\/\//i);
  });
  test(`${file} inlines the favicon from the published asset`, () => {
    const inlined = read(file).match(/<link rel="icon" type="image\/png" sizes="64x64" href="data:image\/png;base64,([A-Za-z0-9+/=]+)">/);
    assert.ok(inlined, `${file} has no inlined favicon`);
    assert.ok(
      Buffer.from(inlined[1], "base64").equals(readFileSync(join(root, "assets/favicon.png"))),
      `${file} favicon does not match assets/favicon.png`,
    );
  });
  test(`${file} inlines the header logo for both themes`, () => {
    const html = read(file);
    // The downloaded file has no assets/ beside it, so the logo has to travel
    // inside the document or the fixed header renders empty when air-gapped.
    assert.match(html, /\.site-logo \{[^}]*background: url\("data:image\/png;base64,[A-Za-z0-9+/=]+"\) center \/ contain no-repeat;/);
    assert.match(html, /:root\[data-theme="light"\] \.site-logo \{ background-image: url\("data:image\/png;base64,[A-Za-z0-9+/=]+"\); \}/);
  });
}

test("the document head declares its link-preview card", () => {
  // Asserted on the template, not the committed artifact: CI rebuilds and
  // commits entropylab.html only after a merge, so the committed artifact on a
  // pull request predates any head change. The build stamps this markup into
  // the output verbatim.
  // The og:image URL is fetched only by link-preview crawlers, never by the
  // app; browsers do not load it, so the offline CSP and the no-egress rule
  // are unaffected. The asset ships in the deployed assets/ directory.
  const template = read("src/index.html");
  for (const tag of [
    '<meta name="description" content="',
    '<meta property="og:title" content="EntropyLab">',
    '<meta property="og:type" content="website">',
    '<meta property="og:url" content="https://entropylab.online/">',
    '<meta property="og:description" content="',
    '<meta property="og:image" content="https://entropylab.online/assets/entropylab-social.png">',
    '<meta property="og:image:width" content="1200">',
    '<meta property="og:image:height" content="630">',
    '<meta name="twitter:card" content="summary_large_image">',
    '<meta name="twitter:image" content="https://entropylab.online/assets/entropylab-social.png">',
  ]) {
    assert.ok(template.includes(tag), `src/index.html is missing ${tag}`);
  }
});

test("the link-preview card asset is a 1200x630 PNG", () => {
  const png = readFileSync(join(root, "assets/entropylab-social.png"));
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.ok(png.subarray(0, 8).equals(signature), "not a PNG file");
  // IHDR width and height are the big-endian uint32s at bytes 16 and 20.
  assert.equal(png.readUInt32BE(16), 1200, "social card width must be 1200");
  assert.equal(png.readUInt32BE(20), 630, "social card height must be 630");
});

test("repository source has no unresolved merge markers", () => {
  const offenders = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const name = entry.name;
      const path = join(dir, name);
      if (name === ".git" || name === "node_modules" || name.endsWith(".png")) continue;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        walk(path);
      } else {
        const lines = readFileSync(path, "utf8").split("\n");
        if (lines.some((line) => /^(<<<<<<<|=======|>>>>>>>)/.test(line))) {
          offenders.push(relative(root, path));
        }
      }
    }
  };
  walk(root);
  assert.deepEqual(offenders, [], `unresolved merge markers in: ${offenders.join(", ")}`);
});

test("GitHub Actions are pinned to commit SHAs", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const uses = [...workflow.matchAll(/^\s*-?\s*uses:\s*(\S+)/gm)].map((match) => match[1]);
  assert.ok(uses.length >= 5, "expected third-party actions in ci-cd.yml");
  for (const spec of uses) {
    assert.match(spec, /@[0-9a-f]{40}$/, `${spec} must be pinned to a 40-character commit SHA`);
  }
  assert.match(read(".github/dependabot.yml"), /package-ecosystem:\s*github-actions/);
});
