"""Binary Audit — 静态二进制审计 (import 表扫描 + 硬编码密钥检测).

Usage:
    from audit.binary_audit import BinaryAuditor
    auditor = BinaryAuditor()
    findings = auditor.audit("target_binary")
    for f in findings:
        print(f"{f.severity}: {f.description}")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class BinaryAuditFinding:
    """A vulnerability finding in a binary."""
    file_path: str
    function_name: str = ""
    vulnerability: str = ""
    severity: str = ""           # critical | high | medium | low | info
    line_or_address: str = ""    # Source line or hex address
    description: str = ""
    evidence: str = ""
    cwe: str = ""
    confidence: float = 0.0
    source: str = "static"


class BinaryAuditor:
    """二进制静态审计器 (import 表扫描 + 硬编码密钥检测).

    Usage:
        auditor = BinaryAuditor()
        findings = auditor.audit("binary")
    """

    # Imports that always warrant investigation
    HIGH_RISK_IMPORTS: Dict[str, Dict[str, str]] = {
        "strcpy": {"vuln": "Buffer Overflow", "severity": "critical",
                   "cwe": "CWE-120", "desc": "Unbounded string copy — stack buffer overflow risk"},
        "strcat": {"vuln": "Buffer Overflow", "severity": "critical",
                   "cwe": "CWE-120", "desc": "Unbounded string concatenation"},
        "gets": {"vuln": "Buffer Overflow", "severity": "critical",
                 "cwe": "CWE-120", "desc": "Removed from C11 — never safe"},
        "sprintf": {"vuln": "Buffer Overflow", "severity": "critical",
                    "cwe": "CWE-120", "desc": "Unbounded formatted write"},
        "system": {"vuln": "Command Injection", "severity": "critical",
                   "cwe": "CWE-78", "desc": "Shell command execution — check input"},
        "popen": {"vuln": "Command Injection", "severity": "critical",
                  "cwe": "CWE-78", "desc": "Shell pipe — check input"},
        "execve": {"vuln": "Command Injection", "severity": "critical",
                   "cwe": "CWE-78", "desc": "Process execution — check arguments"},
        "printf": {"vuln": "Format String", "severity": "high",
                   "cwe": "CWE-134", "desc": "Potential format string — check if user-controlled"},
        "fprintf": {"vuln": "Format String", "severity": "high",
                    "cwe": "CWE-134", "desc": "Potential format string"},
        "memcpy": {"vuln": "Buffer Overflow", "severity": "high",
                   "cwe": "CWE-120", "desc": "Check size parameter for overflow"},
        "read": {"vuln": "Buffer Overflow", "severity": "medium",
                 "cwe": "CWE-120", "desc": "Check buffer size bounds"},
        "recv": {"vuln": "Buffer Overflow", "severity": "medium",
                 "cwe": "CWE-120", "desc": "Network receive — check buffer size"},
        "malloc": {"vuln": "Integer Overflow", "severity": "medium",
                   "cwe": "CWE-190", "desc": "Check allocation size calculation"},
        "realloc": {"vuln": "Integer Overflow", "severity": "medium",
                    "cwe": "CWE-190", "desc": "Check new size calculation"},
        "mmap": {"vuln": "Memory Mapping", "severity": "low",
                 "cwe": "CWE-119", "desc": "Check PROT flags and size"},
        "mprotect": {"vuln": "Memory Protection", "severity": "medium",
                     "cwe": "CWE-284", "desc": "Making memory executable — check input"},
    }

    def audit(self, binary_path: str) -> List[BinaryAuditFinding]:
        """Static binary audit: import table + strings analysis."""
        findings: List[BinaryAuditFinding] = []
        if not Path(binary_path).exists():
            return findings

        # Static import scan
        imports = self._extract_imports(binary_path)
        for func_name in imports:
            if func_name in self.HIGH_RISK_IMPORTS:
                info = self.HIGH_RISK_IMPORTS[func_name]
                findings.append(BinaryAuditFinding(
                    file_path=binary_path,
                    function_name=func_name,
                    vulnerability=info["vuln"],
                    severity=info["severity"],
                    line_or_address="(imported)",
                    description=info["desc"],
                    evidence=f"Import: {func_name}",
                    cwe=info["cwe"],
                    confidence=0.7,
                    source="static",
                ))

        # String analysis: look for hardcoded secrets
        findings.extend(self._find_secrets(binary_path))

        return findings

    def quick_assessment(self, binary_path: str) -> Dict[str, Any]:
        """Quick risk assessment: count findings + exploitability score."""
        findings = self.audit(binary_path)

        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")

        # Exploitability score: 0–100
        score = min(100, critical * 20 + high * 10 + medium * 5)

        return {
            "binary": binary_path,
            "total_findings": len(findings),
            "critical": critical, "high": high, "medium": medium,
            "exploitability_score": score,
            "assessment": "HIGH_RISK" if score >= 50 else "MEDIUM" if score >= 20 else "LOW",
            "recommendation": (
                "立即审计并加固" if score >= 50 else
                "建议安全review" if score >= 20 else
                "低风险，定期扫描即可"
            ),
        }

    # ── Private: Import extraction ───────────────────────────────────────

    def _extract_imports(self, binary_path: str) -> List[str]:
        """Extract imported function names from binary."""
        imports: List[str] = []
        import subprocess

        tools = ["objdump", "llvm-objdump", "nm", "strings"]
        for tool in tools:
            try:
                result = subprocess.run(
                    [tool, "-T", binary_path] if tool in ("objdump", "llvm-objdump")
                    else [tool, binary_path],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout:
                    # Parse symbol names
                    for func_name in self.HIGH_RISK_IMPORTS:
                        if func_name in result.stdout:
                            imports.append(func_name)
                    break
            except Exception:
                continue

        return list(set(imports))

    # ── Private: Secret detection ───────────────────────────────────────

    _MAX_BINARY_SIZE = 100 * 1024 * 1024  # 100MB limit to prevent OOM

    def _find_secrets(self, binary_path: str) -> List[BinaryAuditFinding]:
        """Find hardcoded secrets in binary strings."""
        findings: List[BinaryAuditFinding] = []
        try:
            fpath = Path(binary_path)
            fsize = fpath.stat().st_size
            if fsize > self._MAX_BINARY_SIZE:
                return findings  # skip oversized binaries
            data = fpath.read_bytes()
            text = data.decode("ascii", errors="ignore")

            # Simple patterns
            import re
            patterns = {
                "API Key": r'(?:api[_-]?key|apikey|API_KEY)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]',
                "Password": r'(?:password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]{4,}[\'"]',
                "Token": r'(?:token|jwt|bearer)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]',
                "URL": r'https?://[^\s\x00]{8,}',
                "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                "Private Key": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            }

            for name, pattern in patterns.items():
                matches = re.findall(pattern, text, re.IGNORECASE)
                for m in matches[:3]:  # Max 3 per type
                    findings.append(BinaryAuditFinding(
                        file_path=binary_path,
                        vulnerability=f"Hardcoded {name}",
                        severity="high" if name in ("Password", "Private Key", "Token") else "medium",
                        description=f"Hardcoded {name} found in binary",
                        evidence=m[:80],
                        confidence=0.9,
                        source="static",
                    ))

        except Exception:
            pass

        return findings


# ── CLI Integration ──────────────────────────────────────────────────────────

def audit_binary(binary_path: str) -> Dict[str, Any]:
    """CLI-friendly one-shot binary audit.

    Returns dict with findings summary + exploit recommendation.
    """
    auditor = BinaryAuditor()
    assessment = auditor.quick_assessment(binary_path)

    # Recommend next step
    assessment["next_action"] = (
        "深入逆向分析或提交安全 review"
        if assessment["exploitability_score"] >= 30 else
        "继续静态分析或手动逆向"
    )

    return assessment
