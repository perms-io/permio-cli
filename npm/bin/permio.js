#!/usr/bin/env node
"use strict";
// Runs the permio binary, downloading it first if needed (e.g. when installed
// with --ignore-scripts, or via npx). Exit code and stdio pass straight through.

const { spawnSync } = require("node:child_process");
const { install } = require("../lib/install.js");

install()
  .then((bin) => {
    const res = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
    if (res.error) {
      console.error(`permio: failed to run ${bin}: ${res.error.message}`);
      process.exit(2);
    }
    if (res.signal) process.kill(process.pid, res.signal);
    process.exit(res.status ?? 2);
  })
  .catch((err) => {
    console.error(String(err.message || err));
    process.exit(2);
  });
