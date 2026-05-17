"""Textual-based TUI for SprayMaster.

The Textual import is deferred via PEP 562 ``__getattr__`` so that sibling
modules in this package (notably ``spraymaster.tui.runner``, which is reused
by the web UI) can be imported without dragging in the optional ``textual``
dependency.
"""

from __future__ import annotations

__all__ = ["SprayMasterTUI", "run"]


def __getattr__(name: str):
    if name in __all__:
        from spraymaster.tui.app import SprayMasterTUI, run

        return {"SprayMasterTUI": SprayMasterTUI, "run": run}[name]
    raise AttributeError(f"module 'spraymaster.tui' has no attribute {name!r}")
