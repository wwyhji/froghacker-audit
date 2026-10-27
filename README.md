# FrogHacker Audit 🔍

<div align="center">

**代码静态安全审计（开源版）** — regex 快扫 · AST 污点追踪 · 二进制静态

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](./pyproject.toml)
[![零依赖](https://img.shields.io/badge/依赖-纯标准库-important.svg)]()

响应时代号召，开源蛙客网络安全分析自动化平台的**代码审计模块**。

</div>

## 这是什么

蛙客（FrogHacker）是攻·防·取三端共生的安全分析自动化平台。本仓库开源的是其中的**代码审计模块**：给一段代码（或二进制），快速扫出安全漏洞。两层检测互补——

- **快层（regex）**：50+ 危险模式规则，秒级扫描
- **深层（AST taint）**：抽象语法树污点追踪，「用户输入 → 危险 sink」的数据流

## 🗺️ 蛙客开源仓库导航

蛙客平台按能力拆为五个独立仓库，本仓库是其中的**代码审计模块**：

| 仓库 | 定位 |
|------|------|
| [froghacker-defense](https://github.com/wwyhji/froghacker-defense) | 防御端（蓝队）：检测规则 / 蜜罐 / IDS / 防火墙 / 加固 |
| [froghacker-reveng](https://github.com/wwyhji/froghacker-reveng) | 逆向关联追踪引擎：APK 逆向找 key |
| [froghacker-ant-swarm](https://github.com/wwyhji/froghacker-ant-swarm) | 蚁群协作调度底座：多 Agent 任务分配 |
| [froghacker-antihallucination](https://github.com/wwyhji/froghacker-antihallucination) | 算法抗幻觉：确定性验证 + 事实断言裁决 |
| **[froghacker-audit](https://github.com/wwyhji/froghacker-audit)** | 代码静态安全审计：regex + AST 污点（本仓库） |

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

上述方案已申请发明专利（申请日 2026-10-13）。本仓库仅开源业界通用的代码静态审计能力，**不构成**对上述专利技术方案的实施许可。

## 📁 目录结构

```
froghacker-audit/
├── LICENSE               Apache-2.0
├── NOTICE                专利保留声明
├── MANIFEST.md           文件清单与剥离说明
├── pyproject.toml        打包配置
├── audit/
│   ├── __init__.py
│   ├── base.py           regex 扫描器 + 50+ 规则
│   ├── taint.py          AST 污点追踪引擎
│   ├── binary_audit.py   静态二进制审计（import 表 + 硬编码密钥）
│   ├── rules.py          兼容 shim（re-export）
│   └── deep.py           兼容 shim（re-export）
└── tests/                20 个测试
```

## 📄 许可证

Apache License 2.0，© 2026 FrogHacker (wwyhji)。专利保留声明见 [NOTICE](./NOTICE)。
