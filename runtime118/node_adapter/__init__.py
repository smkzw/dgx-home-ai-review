# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Restricted node-lifecycle adapter package (HX side + Spark forced command).

Contents:

- ``protocol``      : bounded strict-JSON wire helpers (client side).
- ``client``        : ``NodeAdapter`` implementing the frozen v2 adapter contract
  over a hardened ``ssh`` argv transport with a durable owner-intent journal.
- ``node_wrapper``  : standalone Spark-side forced-command entrypoint; it is
  deliberately self-contained and does NOT import this package at runtime.

Importing this package only prepares ``sys.path`` so the frozen ``control_plane``
package next door is importable; it performs no I/O and contacts nothing.
"""
from __future__ import annotations
import sys
from pathlib import Path
_RUNTIME_ROOT = Path(__file__).resolve().parent.parent
if str(_RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(_RUNTIME_ROOT))
__all__ = ['client', 'node_wrapper', 'protocol']
