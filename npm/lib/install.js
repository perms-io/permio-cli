"use strict";
// Downloads the permio binary that matches this package's version from the
// GitHub release, verifies it against the release's checksums.txt, and
// extracts it next to this package. Uses only Node built-ins (Node 18+).
//
// Environment:
//   PERMIO_CLI_DOWNLOAD_BASE  base URL instead of the GitHub releases URL
//                             (files are fetched from <base>/<file>)
//   PERMIO_CLI_BINARY         path to an existing permio binary; skips the download

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const REPO = "perms-io/permio-cli";
const pkg = require("../package.json");
const version = pkg.version;

const PLATFORMS = { darwin: "darwin", linux: "linux", win32: "windows" };
const ARCHES = { x64: "amd64", arm64: "arm64" };

function target() {
  const goos = PLATFORMS[process.platform];
  const goarch = ARCHES[process.arch];
  if (!goos || !goarch) {
    throw new Error(
      `permio: no prebuilt binary for ${process.platform}/${process.arch}. ` +
        `Install from source with: go install github.com/${REPO}/cmd/permio@latest`,
    );
  }
  const ext = goos === "windows" ? "zip" : "tar.gz";
  return { goos, goarch, archive: `permio_${version}_${goos}_${goarch}.${ext}` };
}

function binaryPath() {
  if (process.env.PERMIO_CLI_BINARY) return process.env.PERMIO_CLI_BINARY;
  const name = process.platform === "win32" ? "permio.exe" : "permio";
  return path.join(__dirname, "..", "vendor", name);
}

function baseURL() {
  const base = process.env.PERMIO_CLI_DOWNLOAD_BASE || `https://github.com/${REPO}/releases/download/v${version}`;
  return base.replace(/\/+$/, "");
}

async function download(url) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`permio: download failed: ${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

async function install() {
  const dest = binaryPath();
  if (fs.existsSync(dest)) return dest;
  const { archive } = target();
  const base = baseURL();
  const [data, sums] = await Promise.all([download(`${base}/${archive}`), download(`${base}/checksums.txt`)]);
  const want = sums
    .toString("utf8")
    .split("\n")
    .map((line) => line.trim().split(/\s+/))
    .find((parts) => parts[1] === archive);
  if (!want) throw new Error(`permio: ${archive} is not listed in checksums.txt`);
  const got = crypto.createHash("sha256").update(data).digest("hex");
  if (got !== want[0]) throw new Error(`permio: checksum mismatch for ${archive}`);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "permio-"));
  try {
    const file = path.join(tmp, archive);
    fs.writeFileSync(file, data);
    // bsdtar (macOS, Windows 10+) and GNU tar both read .tar.gz; bsdtar also reads .zip.
    execFileSync("tar", ["-xf", file, "-C", tmp], { stdio: "ignore" });
    const name = process.platform === "win32" ? "permio.exe" : "permio";
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(path.join(tmp, name), dest);
    fs.chmodSync(dest, 0o755);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  return dest;
}

module.exports = { install, binaryPath, target };

if (require.main === module) {
  install().catch((err) => {
    // A failed postinstall must not break `npm install`; bin/permio.js retries on first run.
    if (process.argv.includes("--postinstall")) {
      console.warn(String(err.message || err));
      console.warn("permio: will retry the download when permio is first run.");
      return;
    }
    console.error(String(err.message || err));
    process.exitCode = 1;
  });
}
