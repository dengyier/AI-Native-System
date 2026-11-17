# P6 LangGraph 编排与断点恢复验收

## 实现范围

- LangGraph 1.2.22 负责阶段推进、条件分支、受限只读检查的并行汇聚与有限重试。每次推进最多推进一个模型阶段或一个已登记动作。并行检查只用原有的身份、语义与权限读取路径，Stage 仍使用相同的模型入口和任务预算。
- 新任务随企业发布选择 LangGraph 并固化图版本和绝对截止时间。历史任务继续由原后端推进。检查点版本不兼容会拒绝恢复并保留检查点与权威记录。任务过期仍可退出队列。
- LangGraph 在原有 `awaiting_approval` 状态中断。恢复读取 PostgreSQL 中的真实审批记录。写入继续走 Runtime 的事实复查、OpenWorkProof 授权消费和单次操作登记。远端结果不明时，沿原操作 ID 查询，并复用 P4 对账及签名回执。
- 官方 `langgraph-checkpoint-postgres` 3.2.1 将检查点保存在独立 schema。检查点保存图绑定、游标、轮次和布尔检查结果。阶段输入、业务证据、审批与授权记录由原 PostgreSQL 业务表保存。推进受按线程的数据库会话锁保护，崩溃后可以重连读取。
- 两类存储提交边界彼此独立。恢复时先核对业务状态与预期节点。只要一个阶段或效果已提交，就复用原阶段记录、操作或证据。若进程在模型请求后、阶段提交前退出，恢复可产生新的模型尝试，P5 仍按实际返回或未报告的用量记账。
- 租户队列按未结束图任务计数，达到容量会拒绝新提交。`p6 work` 每轮每租户领取一个任务，按该租户的上次领取时间轮转。绝对截止限制新模型调用、批准和动作派发。已有外部效果仍执行回执查询，原证据保留。

## 配置与运行

在应用定义内添加 `graph` 后，按企业发布流程创建、绑定规则并选择新发布。样例使用两个已注册阶段和两项只读检查。

```json
{
  "version": "workflow-v1",
  "deadline_seconds": 120,
  "checks": ["object_grounded", "knowledge_grounded"],
  "on_check_failure": "retry",
  "max_rounds": 2
}
```

可用检查还有 `relationships_grounded`。`block` 分支执行一轮检查，`retry` 分支可执行二至四轮。每个应用最多配置 16 个阶段，阶段数超过默认的 12 次逻辑模型调用时，显式设置 `max_model_calls`。生成用配置了数据权限与预算的 LiteLLM 路由，本地演示可用 `DemoModel`。

应用库先迁移到 `0016_graph_tasks`。检查点采用 `ai_native_graph` schema，可与 `ai_native` 共用同一 PostgreSQL 数据库。分别为业务 Runtime、检查点迁移和检查点运行配置账号。检查点运行账号使用直连或会话模式连接。

| 角色 | 配置与权限 |
| --- | --- |
| 业务迁移 | `AI_NATIVE_POSTGRES_MIGRATION_DSN`，应用框架迁移 |
| 检查点迁移 | `AI_NATIVE_GRAPH_MIGRATION_DSN`，由 `ai_native_graph` 的所有者执行官方迁移，也可由该迁移角色创建 schema |
| 检查点运行 | `AI_NATIVE_GRAPH_DSN`，对 `ai_native_graph` 授予 `USAGE`。对 `checkpoint_migrations` 授予 `SELECT`，对 `checkpoints`、`checkpoint_blobs` 和 `checkpoint_writes` 授予 `SELECT, INSERT, UPDATE` |
| 业务运行 | 原权限加任务列 `graph_version`、`graph_deadline` 的写入权限，以及 `graph_last_claim` 的更新权限。已有表级 `INSERT/UPDATE` 权限可覆盖。图版本及截止时间由触发器禁止更新 |

使用 `AI_NATIVE_GRAPH_QUEUE_LIMIT` 配置单租户队列容量，默认 100。使用 `AI_NATIVE_GRAPH_MAX_CONNECTIONS` 配置单进程检查点连接上限，默认 4。企业任务通过已配置身份的 API 提交和审批，worker 定期运行有界批次。

```bash
python -m ai_native_system --postgres migrate
python -m ai_native_system --postgres p6 migrate-checkpoints
python -m ai_native_system --postgres p6 work --queue-tenant tenant-a --queue-tenant tenant-b --per-tenant 2
python -B deployment/local-postgres/verify_p6.py
```

## 验证范围

实际 PostgreSQL 18.7 上验证新旧后端行为对照、双阶段交接、跨会话恢复、权限撤销、并发重复推进、预算共享、队列公平和截止。工作进程在权威效果提交后直接退出，重新启动仍只有一条效果、一条授权消费和一条证据。独立 MCP 测试服务在源库提交后退出。重启后图任务沿用原操作，P4 对账队列查得并验证源签回执，源端写入保持一次。框架、检查点和 MCP 参考源测试数据使用同一个 PostgreSQL 实例中的独立 schema 和连接角色。

| 验证方式 | 结果 |
| --- | --- |
| `verify_p6.py` | 33 项通过，含 15 项 PostgreSQL 端到端流程和 5 项 PostgreSQL 检查点测试。业务迁移为 `0016_graph_tasks`，检查点迁移版本为 `9` |
| `verify_migration.py` 与 `verify_runtime.py` | 18 项 PostgreSQL 回归通过 |
| `verify_p4.py` 与 `verify_p5.py` | 35 项工具与证据回归和 28 项模型与观测回归通过 |
| `python -B -m unittest discover -s tests` | 152 项通过。其余 163 项需要各自的专用数据库环境 |

单次模型调用受阶段租约和 P5 发送期限约束，跨阶段和审批等待使用任务绝对截止。任意长运行的租约续期、多副本容量与高可用切换留给部署验收。本次使用受限顺序 Agent、并行只读检查及已经登记的动作序列，后续应用的知识检索与评测使用 P7 接口。

[LangGraph 检查点](https://docs.langchain.com/oss/python/langgraph/persistence) · [持久运行](https://docs.langchain.com/oss/python/langgraph/durable-execution) · [人工中断](https://docs.langchain.com/oss/python/langgraph/interrupts)
