"""PyInstaller entry — kept tiny on purpose so the bundle bootstraps fast."""

from spraymaster.__main__ import _entrypoint

if __name__ == "__main__":
    raise SystemExit(_entrypoint())
