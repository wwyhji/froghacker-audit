# audit-oss 文件清单与剥离说明

> 生成日期：2026-10-26
> 来源仓库：`D:\froghacker`（蛙客 v5.2，主仓库为专有软件）

## 一、开源内容（本仓库）

| 文件 | 能力 | 来源 |
|------|------|------|
| `audit/base.py` | regex 危险模式扫描（Scanner + COMMON_PATTERNS，50+ 规则） | `tools/audit/base.py` |
| `audit/taint.py` | AST 污点追踪（TaintEngine + TAINT_RULES，source→sink 数据流） | `tools/audit/taint.py` |
| `audit/binary_audit.py` | 静态二进制审计（import 表扫描 + 硬编码密钥检测） | `tools/audit/binary_audit.py` |
| `audit/rules.py` `audit/deep.py` | 向后兼容 shim（re-export） | `tools/audit/{rules,deep}.py` |

## 二、剥离内容（**不在**本仓库）

| 位置 | 剥离内容 | 原因 |
|------|---------|------|
| `business_logic.py` | 整个模块（FCA/Petri/KL/Causality 业务逻辑审计四透镜） | 专利04 数学引擎（权4 FCA / 权6 KL / 权7 Petri+因果） |
| `cli.py` | 整个（CLIRegistry 注册 + `--business` 选项） | 平台 CLI 架构 + 依赖 business_logic |
| `__init__.py` `audit_and_store` | KB 存储 + AlphaLoop 摄入 + Discovery 上报 | 平台 KB/飞轮耦合 |
| `binary_audit.py` `_symbolic_audit` | vuln_miner 符号执行（ConcolicExecutor） | 挖洞模块依赖 |
| `binary_audit.py` `_attack_surface_audit` | vuln_miner 攻击面映射（AttackSurfaceMapper） | 挖洞模块依赖 |
| `binary_audit.py` `swallow_trap` | 平台错误记录（4 处） | → 删除（try/except 已兜底） |

## 三、验证

```bash
cd audit-oss
python -m pytest tests/test_audit.py -q   # 20 passed
```

剥离后：纯标准库（re / ast / dataclasses），零第三方依赖，零数学引擎依赖。
