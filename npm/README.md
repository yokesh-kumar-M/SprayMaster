# spraymaster (npm wrapper)

This is a thin Node.js wrapper around the [SprayMaster](https://github.com/yokesh-kumar-M/SprayMaster) Python CLI, so JavaScript-first users can install it with `npm`.

```bash
npm install -g spraymaster
spraymaster --help
```

On first install, the wrapper attempts to install the Python package automatically via `pipx` (preferred) or `pip --user` (fallback). If neither is available, the wrapper will print install hints the first time you run it.

For full documentation, see the [main README](https://github.com/yokesh-kumar-M/SprayMaster).

## Manual install (no npm)

If you'd rather skip the wrapper entirely:

```bash
pipx install spraymaster
# or
pip install spraymaster
```

## Skip auto-install during `npm install`

```bash
SPRAYMASTER_SKIP_PY_INSTALL=1 npm install -g spraymaster
```

## License

Apache 2.0 (as of v2.3.0; earlier published versions were MIT).
