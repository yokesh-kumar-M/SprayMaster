#!/usr/bin/env node
// SprayMaster npm wrapper: locates a Python interpreter and dispatches to the
// installed `spraymaster` CLI (or `python -m spraymaster` as fallback).

"use strict";

const { spawn, spawnSync } = require("child_process");

const PY_PACKAGE = "spraymaster";

function which(cmd) {
  const isWin = process.platform === "win32";
  const probe = isWin ? "where" : "which";
  const r = spawnSync(probe, [cmd], { encoding: "utf8" });
  if (r.status === 0 && r.stdout) {
    return r.stdout.split(/\r?\n/).filter(Boolean)[0];
  }
  return null;
}

function findEntrypoint() {
  // 1. Prefer the installed `spraymaster` console script (works if pipx or
  //    pip placed it on PATH).
  const direct = which("spraymaster");
  if (direct) {
    return { cmd: direct, args: [] };
  }

  // 2. Fall back to `python -m spraymaster` using whichever Python is around.
  for (const py of ["python3", "python", "py"]) {
    const found = which(py);
    if (found) {
      // `py` on Windows needs an explicit version selector for python3.
      const args = py === "py" ? ["-3", "-m", PY_PACKAGE] : ["-m", PY_PACKAGE];
      return { cmd: found, args };
    }
  }
  return null;
}

function printSetupHelp() {
  process.stderr.write(
    [
      "",
      "  SprayMaster: the Python package isn't installed yet.",
      "",
      "  This npm package is a thin launcher for the Python CLI. Install it with:",
      "",
      "      pipx install spraymaster          # recommended",
      "      pip  install --user spraymaster   # fallback",
      "",
      "  Then re-run:  spraymaster --help",
      "",
    ].join("\n"),
  );
}

function main() {
  const entry = findEntrypoint();
  if (!entry) {
    printSetupHelp();
    process.exit(127);
  }

  const child = spawn(entry.cmd, [...entry.args, ...process.argv.slice(2)], {
    stdio: "inherit",
    env: { ...process.env, PYTHONIOENCODING: "utf-8" },
  });

  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code === null ? 1 : code);
    }
  });

  child.on("error", (err) => {
    process.stderr.write(`spraymaster: failed to launch — ${err.message}\n`);
    process.exit(1);
  });
}

main();
