"""Backward-compatible shim — re-exports from taint.py.

Deprecated: use `from audit.taint import ...` directly.
"""

from .taint import (  # noqa: F401
    DeepScanner,
    TaintFinding,
    run_deep,
)
