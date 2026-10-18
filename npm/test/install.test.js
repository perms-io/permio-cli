"use strict";
// Exercises the download + checksum + extract path against a local HTTP server
// serving a fake release. Run with: npm test (from npm/).
const test = require("node:test");
const assert = require("node:assert");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const pkgDir = path.join(__dirname, "..");
const vendor = path.join(pkgDir, "vendor");

test("downloads, verifies and runs the binary", { skip: process.platform === "win32" }, async () => {
  const { target } = require("../lib/install.js");
  const { archive } = target();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "permio-npm-test-"));
  fs.writeFileSync(path.join(work, "permio"), "#!/bin/sh\necho fake permio $@\nexit 3\n", { mode: 0o755 });
  execFileSync("tar", ["-czf", path.join(work, archive), "-C", work, "permio"]);
  const data = fs.readFileSync(path.join(work, archive));
  let sums = `${crypto.createHash("sha256").update(data).digest("hex")}  ${archive}\n`;

  const server = http.createServer((req, res) => {
    if (req.url === `/${archive}`) return res.end(data);
    if (req.url === "/checksums.txt") return res.end(sums);
    res.statusCode = 404;
    res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const env = { ...process.env, PERMIO_CLI_DOWNLOAD_BASE: base };
  delete env.PERMIO_CLI_BINARY;
  try {
    fs.rmSync(vendor, { recursive: true, force: true });
    const run = () => new Promise((resolve) => {
      const child = require("node:child_process").spawn(process.execPath, [path.join(pkgDir, "bin", "permio.js"), "version"], { env });
      let out = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (out += d));
      child.on("close", (code) => resolve({ code, out }));
    });
    let r = await run();
    assert.strictEqual(r.code, 3, r.out); // exit code passes through
    assert.match(r.out, /fake permio version/);

    // A bad checksum is refused.
    fs.rmSync(vendor, { recursive: true, force: true });
    sums = `${"0".repeat(64)}  ${archive}\n`;
    r = await run();
    assert.strictEqual(r.code, 2);
    assert.match(r.out, /checksum mismatch/);
  } finally {
    server.close();
    fs.rmSync(vendor, { recursive: true, force: true });
    fs.rmSync(work, { recursive: true, force: true });
  }
});
