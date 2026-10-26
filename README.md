# FrogHacker Audit — 代码静态安全审计

给一段代码（文件或目录），快速扫出安全漏洞。两层检测：

- **快层（regex）**：50+ 危险模式规则——`eval`/`exec`/`system`、弱加密（`md5`/`sha1`）、硬编码密钥等
- **深层（AST taint）**：抽象语法树污点追踪——「用户输入 → 危险 sink」的数据流（SQL 注入、命令注入、XSS 等）

## 用法

```python
from audit import run, run_deep, format_results

results = run("target.py")           # 快层 regex 扫描
deep = run_deep("target.py")         # 深层 AST 污点追踪
print(format_results(results))
```

二进制静态审计：

```python
from audit.binary_audit import BinaryAuditor

auditor = BinaryAuditor()
findings = auditor.audit("target_binary")    # import 表 + 硬编码密钥
for f in findings:
    print(f"{f.severity}: {f.description}")
```

## 依赖

纯 Python 标准库（`re` / `ast` / `dataclasses`），零第三方依赖。

## 许可

Apache-2.0，见 LICENSE。
