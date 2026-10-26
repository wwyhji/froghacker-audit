# FrogHacker Audit 🔍

代码静态安全审计——给一段代码，快速扫出安全漏洞。

## 这是什么

「蛙客网络安全分析自动化平台」的代码审计模块开源版。两层检测：

- **快层（regex）**：50+ 危险模式规则，秒级扫描
- **深层（AST taint）**：抽象语法树污点追踪，「用户输入 → 危险 sink」的数据流

纯 Python 标准库（`re` / `ast` / `dataclasses`），零第三方依赖。

## ✨ 特性

- **两层互补**：regex 快扫（危险模式）+ AST 深扫（数据流）
- **二进制审计**：import 表扫描（危险函数）+ 硬编码密钥检测
- **可解释**：每个发现带漏洞类型 / 严重度 / CWE / 行号 / 代码片段 / 置信度
- **零依赖**：只用标准库，装上即用

## 🚀 快速上手

```bash
pip install -e .        # 或直接 clone 后使用
```

### 代码审计

```python
from audit import run, run_deep, format_results

results = run("target.py")           # 快层 regex 扫描
deep = run_deep("target.py")         # 深层 AST 污点追踪
print(format_results(results))
```

### 二进制审计

```python
from audit.binary_audit import BinaryAuditor

auditor = BinaryAuditor()
for f in auditor.audit("target_binary"):
    print(f"{f.severity}: {f.description}")
```

## 🛡️ 检测覆盖

| 层 | 覆盖 |
|----|------|
| regex 快层 | 50+ 规则：`eval`/`exec`/`system`、SQL 注入、弱加密（`md5`/`sha1`）、硬编码密钥等危险模式 |
| AST 污点深层 | source（`request`/`input`）→ sink（`execute`/`query`）数据流：SQL 注入、命令注入、XSS、SSRF 等 |
| 二进制静态 | 16 个危险 import（`strcpy`/`system`/`mprotect`…）+ 硬编码密钥（API Key/Password/Token/私钥）|

## 🛡️ 专利保护与开源边界

本仓库开源的是**代码静态安全审计**（regex + AST taint + 二进制静态扫描）。

以下能力**不在**本仓库（受专利保护或平台耦合，见 MANIFEST.md / NOTICE）：

- 业务逻辑审计（FCA / Petri 网 / KL 信息论 / 因果推断）
- 符号执行、攻击面映射（挖洞管线）
- 知识库摄入、自充飞轮（AlphaLoop）

## 📁 目录结构

```
audit/
  base.py           regex 扫描器 + 50+ 规则
  taint.py          AST 污点追踪引擎
  binary_audit.py   静态二进制审计（import 表 + 硬编码密钥）
  rules.py          兼容 shim（re-export）
  deep.py           兼容 shim（re-export）
tests/              20 个测试
```

## 📄 许可证

Apache-2.0，见 LICENSE。
