"""Backward-compatible shim — re-exports from taint.py.

Deprecated: use `from audit.taint import ...` directly.
"""

from .taint import (  # noqa: F401
    TaintEngine as RuleEngine,
    TaintFinding as AuditFinding,
    TAINT_RULES as OWASP_RULES,
    quick_audit,
    audit_directory,
)
