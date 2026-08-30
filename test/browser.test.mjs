// Runs the assembled application in headless Firefox against a local Node.js
// HTTP server and validates the BIP39/BIP32 vectors, input sanitization,
// same-origin network behavior, hosted presentation, and recovery-sheet
// exports. The in-page instrumentation and suite live alongside this harness.
// Run with `npm run test:browser` or `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import {
  closeSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const resolveFirefox = () => {
  if (process.env.FIREFOX_BINARY) return process.env.FIREFOX_BINARY;
  const tryRun = (bin) => {
    try {
      const result = spawnSync(bin, ["--version"], { stdio: "pipe" });
      if (result.status === 0) return bin;
    } catch {}
    return null;
  };
  for (const bin of ["firefox", "firefox-developer-edition"]) {
    const found = tryRun(bin);
    if (found) return found;
  }
  const platform = process.platform;
  const paths = [];
  if (platform === "darwin") {
    paths.push(
      "/Applications/Firefox Developer Edition.app/Contents/MacOS/firefox",
      "/Applications/Firefox.app/Contents/MacOS/firefox",
    );
  } else if (platform === "win32") {
    paths.push(
      "C:\\Program Files\\Firefox Developer Edition\\firefox.exe",
      "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
      "C:\\Program Files (x86)\\Firefox Developer Edition\\firefox.exe",
      "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
    );
  } else {
    paths.push(
      "/usr/bin/firefox",
      "/usr/bin/firefox-developer-edition",
      "/usr/local/bin/firefox",
      "/usr/local/bin/firefox-developer-edition",
      "/snap/bin/firefox",
      "/snap/bin/firefox-developer-edition",
      "/opt/firefox/firefox",
      "/opt/firefox-developer-edition/firefox",
    );
  }
  for (const p of paths) {
    if (existsSync(p)) return p;
  }
  return "firefox";
};

const firefoxBin = resolveFirefox();

// A snap-confined Firefox (the Ubuntu default: /usr/bin/firefox is a wrapper
// around /snap/bin/firefox) runs with a private /tmp mount namespace, so a
// staging area under os.tmpdir() is invisible to the browser: the profile,
// the file:// test page, and the download directory all silently miss and
// the suite times out. Unconfined builds (CI runners, mozilla.org tarballs,
// macOS, Windows) share the host's view of the filesystem.
const isSnapConfined = (() => {
  if (process.platform !== "linux") return false;
  try {
    const onPath = firefoxBin.includes("/")
      ? firefoxBin
      : (process.env.PATH ?? "").split(":").filter(Boolean)
          .map((dir) => join(dir, firefoxBin)).find((candidate) => existsSync(candidate));
    if (!onPath) return false;
    const resolved = realpathSync(onPath);
    if (resolved.split("/").includes("snap")) return true;
    // The Ubuntu transition wrapper is a tiny shell script, not an ELF binary.
    if (statSync(resolved).size < 1024 * 1024) {
      const content = readFileSync(resolved, "utf8");
      if (content.includes("/snap/bin") || content.includes("snap install firefox")) return true;
    }
  } catch {}
  return false;
})();

// For a snap-confined browser, stage under the snap's common directory: the
// one path the sandbox and this harness both see at the identical absolute
// location. Everywhere else, keep using the system temp dir.
const stagingBase = () => {
  if (!isSnapConfined) return tmpdir();
  const base = join(homedir(), "snap", "firefox", "common");
  mkdirSync(base, { recursive: true });
  return base;
};

const appVersion = JSON.parse(read("package.json")).version;
const appFile = "entropylab.html";
const appSource = join(root, appFile);

// Stage the site exactly the way scripts/build.mjs publishes it (the compiled
// entropylab.html), and add the instrumented test document and the hostile
// version manifest.
const stageSite = () => {
  const workDir = mkdtempSync(join(stagingBase(), "entropylab-browser-"));
  const siteDir = join(workDir, "site");
  const downloadDir = join(workDir, "downloads");
  const onlineProfile = join(workDir, "profile-online");
  const offlineProfile = join(workDir, "profile-offline");
  mkdirSync(join(siteDir, "assets"), { recursive: true });
  mkdirSync(downloadDir, { recursive: true });
  mkdirSync(onlineProfile, { recursive: true });
  mkdirSync(offlineProfile, { recursive: true });
  cpSync(appSource, join(siteDir, appFile));
  cpSync(join(root, "assets"), join(siteDir, "assets"), { recursive: true });

  const appHtml = read(appFile);
  const instrumentation = read("test/browser-instrumentation.html");
  const suite = read("test/browser-suite.html");

  // Inject the test instrumentation before the application stylesheet.
  const marker = '<style id="btc-calc-style">';
  const markerIndex = appHtml.indexOf(marker);
  if (markerIndex === -1) throw new Error("could not find the application stylesheet marker");
  const stageOne = `${appHtml.slice(0, markerIndex)}${instrumentation}${appHtml.slice(markerIndex)}`;

  // Append the browser suite before the document end.
  const testHtml = `${stageOne.replace(/<\/body>\s*<\/html>\s*$/, "")}${suite}</body></html>\n`;
  const testHtmlPath = join(siteDir, "browser-tests.html");
  writeFileSync(testHtmlPath, testHtml, "utf8");

  writeFileSync(join(workDir, "not-found.txt"), "Not found\n", "utf8");

  const userJs = [
    'user_pref("browser.download.folderList", 2);',
    `user_pref("browser.download.dir", ${JSON.stringify(downloadDir)});`,
    'user_pref("browser.download.useDownloadDir", true);',
    'user_pref("browser.download.alwaysOpenPanel", false);',
    'user_pref("browser.helperApps.neverAsk.saveToDisk", "text/plain,application/octet-stream");',
    'user_pref("browser.shell.checkDefaultBrowser", false);',
    'user_pref("browser.startup.homepage_override.mstone", "ignore");',
    'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
    'user_pref("toolkit.telemetry.enabled", false);',
    "",
  ].join("\n");
  writeFileSync(join(onlineProfile, "user.js"), userJs, "utf8");
  writeFileSync(join(offlineProfile, "user.js"), userJs, "utf8");

  return { workDir, siteDir, downloadDir, onlineProfile, offlineProfile, testHtmlPath };
};

// A real HTTP server: concurrent connections, correct framing, 404s.
const createTestServer = ({ siteDir, testHtmlPath }) => {
  const notFound = { file: join(dirname(testHtmlPath), "..", "not-found.txt"), type: "text/plain; charset=utf-8" };
  const routes = {
    "/": { file: testHtmlPath, type: "text/html; charset=utf-8" },
    "/browser-tests.html": { file: testHtmlPath, type: "text/html; charset=utf-8" },
    [`/${appFile}`]: { file: join(siteDir, appFile), type: "text/html; charset=utf-8" },
  };
  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://localhost").pathname;
    const route = routes[path] ?? { ...notFound, status: 404, reason: "Not Found" };
    response.writeHead(route.status ?? 200, {
      "Content-Type": route.type,
      "Content-Length": statSync(route.file).size,
      "Cache-Control": "no-store",
    });
    response.end(readFileSync(route.file));
  });
  const listen = () => new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
  return { server, listen };
};

const spawnFirefox = (profile, url, logPath) => {
  const logFd = openSync(logPath, "w");
  const process = spawn(firefoxBin, ["--headless", "--new-instance", "--profile", profile, url], {
    stdio: ["ignore", logFd, logFd],
  });
  closeSync(logFd);
  process.on("error", () => {});
  return process;
};

const waitForFile = async (file, timeoutMs) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(file) && statSync(file).size > 0) return true;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return false;
};

const parseReport = (file) => {
  const lines = readFileSync(file, "utf8").trim().split("\n");
  const results = lines.map((line) => {
    const [status, name, error] = line.split("\t");
    return { ok: status === "ok", name: name ?? "", error: error ?? "" };
  });
  return {
    checks: results.length,
    results,
    failures: results.filter((result) => !result.ok),
  };
};

const tail = (file, maxLines = 120) => {
  if (!existsSync(file)) return "";
  return readFileSync(file, "utf8").split("\n").slice(-maxLines).join("\n");
};

test("headless Firefox runs the hosted and offline suites", async () => {
  const versionCheck = spawnSync(firefoxBin, ["--version"], { stdio: "pipe" });
  assert.equal(versionCheck.status, 0, `Firefox is required for the browser tests (tried "${firefoxBin}").`);
  assert.match(appVersion, /^\d+(\.\d+)*$/, `invalid application version in package.json: ${appVersion}`);
  assert.ok(existsSync(appSource), `compiled ${appFile} is missing (run 'npm run build')`);

  const { workDir, siteDir, downloadDir, onlineProfile, offlineProfile, testHtmlPath } = stageSite();
  const { server, listen } = createTestServer({ siteDir, testHtmlPath });
  const browsers = [];
  let port = 0;
  try {
    port = await listen();
    // The HTML export target is fetched here, outside the page: the app's CSP
    // (connect-src 'none') deliberately blocks the in-page fetch the suite
    // used to rely on, so the harness proves the download link serves the
    // current self-contained release.
    const exportResponse = await fetch(`http://127.0.0.1:${port}/${appFile}`);
    assert.ok(exportResponse.ok, `HTML export returned HTTP ${exportResponse.status}`);
    const exportBytes = Buffer.from(await exportResponse.arrayBuffer());
    assert.ok(exportBytes.equals(readFileSync(appSource)), "HTML export is not the current self-contained release");
    const onlineUrl = `http://127.0.0.1:${port}/browser-tests.html?online-preview=1`;
    const offlineUrl = `${pathToFileURL(testHtmlPath).href}?offline-test=1`;
    const onlineLog = join(workDir, "firefox-online.log");
    const offlineLog = join(workDir, "firefox-offline.log");
    browsers.push(spawnFirefox(onlineProfile, onlineUrl, onlineLog));
    browsers.push(spawnFirefox(offlineProfile, offlineUrl, offlineLog));

    const onlineReport = join(downloadDir, "online-results.txt");
    const offlineReport = join(downloadDir, "offline-results.txt");
    const [onlineDone, offlineDone] = await Promise.all([
      waitForFile(onlineReport, 60000),
      waitForFile(offlineReport, 60000),
    ]);
    assert.ok(
      onlineDone && offlineDone,
      `Timed out waiting for Firefox test reports.\n--- firefox-online.log ---\n${tail(onlineLog)}\n--- firefox-offline.log ---\n${tail(offlineLog)}`,
    );

    const online = parseReport(onlineReport);
    const offline = parseReport(offlineReport);
    // Guard against a report that exists because the suite bailed out early:
    // the hosted suite must genuinely run its full battery of checks.
    assert.ok(online.checks >= 20, `online suite report is incomplete: only ${online.checks} checks`);
    assert.ok(offline.checks >= 2, `offline suite report is incomplete: only ${offline.checks} checks`);

    const all = [...offline.results, ...online.results];
    let counter = 0;
    for (const result of all) {
      counter += 1;
      if (result.ok) {
        console.log(`ok ${counter} - ${result.name}`);
      } else {
        console.error(`not ok ${counter} - ${result.name}`);
        console.error(`  ${result.error}`);
      }
    }
    console.log(`1..${counter}`);
    const failures = [...offline.failures, ...online.failures];
    assert.equal(failures.length, 0, `${failures.length} Firefox integration test(s) failed: ${failures.map((f) => `${f.name}: ${f.error}`).join("; ")}`);
    console.log(`All ${counter} cryptographic and browser integration tests passed.`);
  } finally {
    for (const browser of browsers) {
      browser.kill("SIGKILL");
    }
    // Windows CI runners keep Firefox profile files locked briefly after
    // SIGKILL; give the handles time to release before cleanup.
    await new Promise((resolve) => setTimeout(resolve, 500));
    await new Promise((resolve) => server.close(resolve));
    rmSync(workDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  }
});
