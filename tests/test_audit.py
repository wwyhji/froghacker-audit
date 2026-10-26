"""Tests for audit — regex scanner and taint engine."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from audit.base import (
    AuditPattern,
    AuditResult,
    COMMON_PATTERNS,
    Scanner,
    format_results,
    merge_results,
    run,
)
from audit.taint import TAINT_RULES, TaintEngine, TaintFinding, run_deep


# ── Fixture paths ────────────────────────────────────────────────────

@pytest.fixture
def vuln_fixture():
    return Path(__file__).parent / "fixtures" / "audit_vuln.py"

@pytest.fixture
def clean_fixture():
    return Path(__file__).parent / "fixtures" / "audit_clean.py"


# ═══════════════════════════════════════════════════════════════════════
# TestBaseScanner — regex-based scanning (base.py)
# ═══════════════════════════════════════════════════════════════════════

class TestBaseScanner:
    """Tests for regex-based Scanner in base.py."""

    def test_scanner_single_file(self, vuln_fixture):
        """Known-vuln fixture should produce findings."""
        results = run(vuln_fixture)
        assert len(results) > 0, "Should detect vulns in fixture file"
        # Should find at least: hardcoded password, command injection, pickle
        vuln_names = {r.vulnerability for r in results}
        expected = {"Hardcoded Password", "exec() / system() Call",
                    "os.system / os.popen", "Python Pickle Deserialization"}
        found = vuln_names & expected
        assert len(found) >= 1, f"Expected at least one of {expected}, got {vuln_names}"

    def test_scanner_empty(self):
        """Empty code should return 0 findings."""
        scanner = Scanner(source="")
        results = scanner.scan()
        assert len(results) == 0

    def test_scanner_no_vulns(self, clean_fixture):
        """Clean code should produce no findings."""
        results = run(clean_fixture)
        # Hardcoded path "/etc/hostname" shouldn't trigger — it's not a password
        actual = [r for r in results if r.severity in ("critical", "high")]
        assert len(actual) == 0, f"False positives: {actual}"

    def test_scanner_severity_order(self):
        """Results should be sorted: critical → high → medium → low."""
        r1 = AuditResult("A", "low", 1, "", 0.8, "", "", "", [])
        r2 = AuditResult("B", "critical", 1, "", 0.9, "", "", "", [])
        r3 = AuditResult("C", "high", 1, "", 0.7, "", "", "", [])
        sorted_results = merge_results([r1, r2, r3])
        severities = [r.severity for r in sorted_results]
        assert severities == ["critical", "high", "low"]

    def test_merge_dedup(self):
        """Duplicate (vulnerability, line) should keep highest confidence."""
        r1 = AuditResult("SQL Injection", "high", 42, "", 0.5, "", "", "", [])
        r2 = AuditResult("SQL Injection", "high", 42, "", 0.9, "", "", "", [])
        merged = merge_results([r1, r2])
        assert len(merged) == 1
        assert merged[0].confidence == 0.9

    def test_format_results_non_empty(self):
        """format_results should produce readable output."""
        r = AuditResult("Test Vuln", "high", 10, "code", 0.8,
                        "Description", "payload", "CWE-89", [])
        output = format_results([r])
        assert "Test Vuln" in output
        assert "HIGH" in output

    def test_format_results_empty(self):
        """format_results with empty list should show no-findings message."""
        output = format_results([])
        assert "未发现" in output or "no" in output.lower()

    def test_scanner_from_string(self):
        """Scanner should accept raw source string."""
        code = '<?php\n$password = "secret123";\neval($_GET["cmd"]);\n'
        scanner = Scanner(source=code)
        results = scanner.scan()
        assert len(results) > 0

    def test_scanner_add_custom_pattern(self):
        """Custom patterns should be scanned alongside builtins."""
        scanner = Scanner(source="custom_unsafe_func($user_input)")
        scanner.add_pattern(AuditPattern(
            name="Custom Check", regex=r"custom_unsafe_func",
            severity="high", description="Custom", cwe="CWE-999",
            suggested_payload="", references=[],
        ))
        results = scanner.scan()
        assert any("Custom Check" in r.vulnerability for r in results)


# ═══════════════════════════════════════════════════════════════════════
# TestTaintEngine — AST taint analysis (taint.py)
# ═══════════════════════════════════════════════════════════════════════

class TestTaintEngine:
    """Tests for unified TaintEngine in taint.py."""

    def test_taint_source_to_sink(self):
        """input() → os.system() should be detected."""
        code = "def foo():\n    cmd = input('>')\n    os.system(cmd)\n"
        engine = TaintEngine()
        findings = engine.scan(code)
        assert len(findings) > 0
        assert any("cmd" in f.description for f in findings)

    def test_taint_sanitized(self):
        """shlex.quote() sanitized input should NOT be flagged."""
        code = (
            "import shlex\n"
            "def bar():\n"
            "    cmd = input('>')\n"
            "    os.system(shlex.quote(cmd))\n"
        )
        engine = TaintEngine()
        findings = engine.scan(code)
        # No taint findings — sanitized
        taint_findings = [f for f in findings if f.taint_path]
        assert len(taint_findings) == 0, f"Sanitized but flagged: {taint_findings}"

    def test_taint_no_source(self):
        """os.system('static') without user input should not taint-flag."""
        code = "import os\nos.system('ls -la')\n"
        engine = TaintEngine()
        findings = engine.scan(code)
        taint_findings = [f for f in findings if f.taint_path]
        assert len(taint_findings) == 0

    def test_pickle_detected(self):
        """pickle.loads() should be detected as sink-only."""
        code = "import pickle\ndata = pickle.loads(user_bytes)\n"
        engine = TaintEngine()
        findings = engine.scan(code)
        assert any("A06-COMPONENTS" in f.rule_id or "deserialization" in f.title.lower()
                   for f in findings), f"Got: {[(f.rule_id, f.title) for f in findings]}"

    def test_sqli_detected(self):
        """cursor.execute with tainted variable should be detected."""
        code = (
            "def search(db):\n"
            "    name = input('Name: ')\n"
            "    db.cursor.execute(name)\n"
        )
        engine = TaintEngine()
        findings = engine.scan(code)
        assert len(findings) > 0, f"Got 0 findings for SQL injection test"

    def test_cross_function_not_supported(self):
        """Cross-function taint is not supported — should not crash."""
        code = (
            "def get_input():\n"
            "    return input('>')\n"
            "def use_it():\n"
            "    data = get_input()\n"
            "    os.system(data)\n"
        )
        engine = TaintEngine()
        # Should not raise, even if it can't track cross-function
        findings = engine.scan(code)
        assert isinstance(findings, list)

    def test_scan_file(self, vuln_fixture):
        """scan_file should produce findings on the vuln fixture."""
        engine = TaintEngine()
        findings = engine.scan_file(str(vuln_fixture))
        assert len(findings) > 0

    def test_scan_directory(self, vuln_fixture):
        """scan_directory on fixtures dir should find the vuln file."""
        engine = TaintEngine()
        findings = engine.scan_directory(str(vuln_fixture.parent))
        assert len(findings) > 0
        assert any("audit_vuln.py" in f.file_path for f in findings)

    def test_run_deep_file(self, vuln_fixture):
        """run_deep convenience function should return dicts."""
        results = run_deep(str(vuln_fixture))
        assert isinstance(results, list)
        if results:
            assert isinstance(results[0], dict)
            assert "severity" in results[0]

    def test_taint_finding_to_dict(self):
        """TaintFinding.to_dict() should serialize correctly."""
        f = TaintFinding(
            rule_id="TEST-1", category="Test", severity="high",
            title="Test finding", file_path="test.py", line_number=10,
            code_snippet="os.system(cmd)", description="desc",
            cwe="CWE-78", fix_suggestion="fix", taint_path=["src", "sink"],
        )
        d = f.to_dict()
        assert d["rule_id"] == "TEST-1"
        assert d["taint_path"] == ["src", "sink"]

    def test_rule_coverage(self):
        """TAINT_RULES should cover all expected OWASP categories."""
        categories = {r["category"] for r in TAINT_RULES}
        expected = {"Injection", "Cryptographic Failures", "Insecure Design",
                    "Security Misconfiguration", "Vulnerable Components",
                    "Path Traversal", "Server-Side Request Forgery",
                    "Cross-Site Scripting", "Information Disclosure"}
        assert categories == expected


# ═══════════════════════════════════════════════════════════════════════
# TestCLI — end-to-end CLI integration
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
