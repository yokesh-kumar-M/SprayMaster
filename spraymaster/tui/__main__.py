"""Entry shim: ``python -m spraymaster.tui``"""
from spraymaster.tui.app import run

if __name__ == "__main__":
    raise SystemExit(run())
