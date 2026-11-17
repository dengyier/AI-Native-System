# P1a 契约验收

P1a 已通过。新契约由 Python 标准库实现，旧配置沿用原执行器、配置指纹、审批摘要和远端请求标识。[开发计划](superpowers/plans/2026-11-16-six-layer-owp-integration.md) · [能力清单](六层能力核对.md)

| 契约 | 可用能力 | 验收 |
| --- | --- | --- |
| Ontology | 版本化定义与内存校验，覆盖对象、属性、状态、双端关系基数、有效期、事件、声明式规则与动作引用 | 两个独立领域共用元模型，多对多、单位、精度、空值和缺失值均有正反用例 |
| 事实 | 保留租户内规范身份、来源记录、有效与记录时间、来源版本、质量及冲突。读集摘要包含关系或查询集合边界与成员 | 不同来源相同 ID 不合并，新增成员改变摘要，来源代次变化有明确区分 |
| 连接器 | 声明快照、增量、删除、条件写、幂等范围或期限和回执查询能力。支持状态可明确为未知 | 校验快照完成、跨代次游标、重复事件和同事件 ID 的内容变化 |
| 通用动作 | 读、生成、本地写、远端写的参数与目标校验，区分任务、动作实例、操作、尝试和追踪 ID。回执绑定操作、请求摘要和写入目标 | 无目标的读和生成可构造，生成产物校验存储范围，成功、部分成功和未知效果可区分，回执不能报告越界写入 |
| 旧配置 | `Registry.ontology()` 和 `Registry.action_contract(action_id, tools)` 将旧声明投影到新契约。原应用和远端请求继续用原有摘要算法 | 两组旧应用的已知摘要保持一致，现有 SQLite、HTTP 和 MCP 回归通过 |

模块入口见 [Ontology 定义](../ai_native_system/ontology.py)、[事实与连接器](../ai_native_system/fact_contracts.py)、[任务与动作](../ai_native_system/contracts.py) 和 [兼容投影](../ai_native_system/registry.py)。真实规则求值、事实同步和 OWP 执行授权分别由 P2b 和 P3 实施。

完整验收在 Python 3.14.5 和 P0 锁定的 Python 3.12.13 环境各运行一次，两个环境均为 85 项通过和零连接告警。其中 26 项为新增契约用例，59 项为原有回归。在项目根目录复跑：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS=always::ResourceWarning PYTHONTRACEMALLOC=5 \
  python3 -m unittest discover -s tests -v
```

如需单独验收，分别用 `-p test_ontology.py`、`-p test_fact_contracts.py`、`-p test_contracts.py` 运行上述测试入口。
