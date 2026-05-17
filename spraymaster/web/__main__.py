"""Entry shim: ``python -m spraymaster.web``"""
from spraymaster.web.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
