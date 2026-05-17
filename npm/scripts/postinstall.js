#!/usr/bin/env node
// Best-effort: install the Python `spraymaster` package on first npm install.
// Failures are non-fatal — users get a friendly hint on first run instead.

"use strict";

const { spawnSync } = require("child_process");

const PKG = "spraymaster";

function has(cmd) {
  const probe = process.platform === "win32" ? "where" : "which";
  return spawnSync(probe, [cmd]).status === 0;
}

function run(cmd, args) {
  process.stdout.write(`spraymaster: $ ${cmd} ${args.join(" ")}\n`);
  const r = spawnSync(cmd, args, { stdio: "inherit" });
  return r.status === 0;
}

function tryInstall() {
  // Skip when invoked in CI / sandboxed publish flows.
  if (process.env.SPRAYMASTER_SKIP_PY_INSTALL) {
    process.stdout.write("spraymaster: SPRAYMASTER_SKIP_PY_INSTALL set — skipping Python install.\n");
    return true;
  }

  // 1. If `spraymaster` is already on PATH, we're done.
  if (has(PKG)) {
    process.stdout.write("spraymaster: Python CLI already installed — skipping.\n");
    return true;
  }

  // 2. Prefer pipx (isolated venv, doesn't pollute system Python).
  if (has("pipx") && run("pipx", ["install", PKG])) {
    return true;
  }

  // 3. Fall back to user-site pip install.
  for (const py of ["python3", "python"]) {
    if (has(py) && run(py, ["-m", "pip", "install", "--user", PKG])) {
      return true;
    }
  }

  return false;
}

const ok = tryInstall();
if (!ok) {
  process.stdout.write(
    [
      "",
      "  spraymaster: couldn't auto-install the Python CLI.",
      "  This is fine — the wrapper will print install hints the first time you run it.",
      "",
      "  To install manually:",
      "      pipx install spraymaster",
      "  Or:",
      "      pip install --user spraymaster",
      "",
    ].join("\n"),
  );
}

// Always exit 0 — never break `npm install`.
process.exit(0);
