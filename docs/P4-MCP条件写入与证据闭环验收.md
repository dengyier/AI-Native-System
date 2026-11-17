# P4 MCP 条件写入与证据闭环验收

## 已实现

| 能力 | 框架行为 |
| --- | --- |
| 官方 SDK 工具注册 | 固定 MCP Python SDK 2.3.0，支持 Streamable HTTP 和 stdio。发布固定目的地、执行与查询工具名、输入输出 Schema 摘要。只调用已登记工具。stdio 由独立清单固定程序、参数、工作目录和显式环境变量。HTTP 条件写入和查询分别使用凭据。 |
| 源侧条件写入 | 运行器把同源的主要对象和规则读取集中的版本条件纳入 OWP 签名请求。独立源服务在一个 PostgreSQL 事务内验证签名、动作、原生身份映射、版本及状态，提交写入、去重记录及签名回执。任一条件不满足时，业务修改为零。 |
| 外部条件边界 | 无法在单个已登记事务内保护的规则依赖返回人工核对。独立源之间仍可同步事实。自动写入只使用能够被同一个源事务锁定并核验的执行条件。来源须让规则相关变化推进原生版本。跨源代次需要使用不会复用的版本标识，或将代次编码进版本。参考源使用随机版本标识。 |
| 签名回执 | 使用独立源公钥验证源身份、请求摘要、授权摘要、受影响对象及原生版本。旧版内部投影计数继续兼容。原生版本可为不透明标识，并由事实回流依据精确比较。相同状态而版本不符仍保留冲突。 |
| 回执与证据 | 派发前登记持久对账任务。未知结果使用租约、退避、限流及有限尝试查询原操作，耗尽转人工查询。源签回执与执行方签名证据分别存档，原件和脱敏视图分开。PG 引用带文件摘要，可检查和恢复丢失或损坏的文件。 |
| 多步骤与补偿 | 可把多个已注册任务按顺序关联。每步独立使用 OWP 授权和操作 ID，保留各步结果与效果。后续步骤失败时记录部分成功。补偿关联独立任务，仍需完整审批和授权。 |

MCP 传输与工具接口参见 [官方 SDK 传输文档](https://py.sdk.modelcontextprotocol.io/client/transports/) 与 [工具协议](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)。源执行与回执格式见 [企业动作 profile](../schemas/ai-native-action-v0.1/README.md)。

## 配置与恢复

1. 安装锁定的 PostgreSQL 与集成依赖，把框架主库迁移至 `0013_p4_execution`。现有 PostgreSQL 运行账号增加 `p4_sequence_steps` 的 SELECT。P4 运行账号读取并追加对账队列、读取租约以及更新回流的预期源版本。控制账号管理步骤关系与补偿关联。
2. 在可信工具配置中登记 SDK 传输、派发和查询工具、双方 Schema 摘要、请求超时、幂等与来源信任材料。条件写工具需要 OpenWorkProof 发布、绑定的 P2b 事实规则、独立查询身份和源回执公钥。兼容的旧版 HTTP/MCP 配置继续使用旧契约。
3. 条件写入的 Streamable HTTP 使用 HTTPS 或验收时的 loopback。stdio 的 `launch` 从 `AI_NATIVE_MCP_STDIO_ALLOWLIST` 指向的独立 JSON 文件取值，其中每项为 `command`、`args`、`cwd`，可选 `env` 将子进程变量名绑定到显式环境变量。官方 SDK 双传输均已实际测试。源签条件写的部署入口采用双凭据 HTTP。
4. `AI_NATIVE_P4_DELIVERY_DSN` 的队列角色只更新领取、期限和状态列，并负责发布证据引用。签名端沿用 `AI_NATIVE_OWP_EVIDENCE_DSN`，独立于源回执和 OWP 授权签发角色。证据文件目录由可信进程持有，通过脱敏视图提供普通读取。
5. 对账执行 `p4 drain reconcile`，证据发布执行 `p4 drain evidence`。耗尽后的 `p4 query-one` 只查询指定操作，并保留原自动尝试次数。未知或 `not_found` 不授予重新派发资格。证据完整性恢复通过 `p4 proof --repair`，独立验签通过 `p4 verify-source` 或 `owp verify-evidence`。已核验的源写入和原操作台账不会因证据签名失败而重跑。

条件工具配置的结构示例。摘要通过可信的工具发布流程取得，不从未登记服务自动采信。

~~~json
{
  "tools": [{
    "name": "source.verify",
    "version": "1",
    "transport": "mcp-sdk-http",
    "endpoint": "https://source.example/mcp",
    "execute_tool": "apply_source_action",
    "lookup_tool": "lookup_source_action",
    "execute_schema_digest": "REPLACE_WITH_PINNED_SHA256",
    "lookup_schema_digest": "REPLACE_WITH_PINNED_SHA256",
    "token_env": "SOURCE_EXECUTE_TOKEN",
    "lookup_token_env": "SOURCE_LOOKUP_TOKEN",
    "idempotent": true,
    "source": {
      "source": "inventory",
      "lookup_principal": "source-lookup",
      "retention_seconds": 86400,
      "receipt_public_keys": ["/secure/source-public.pem"]
    }
  }]
}
~~~

~~~bash
python -m ai_native_system --postgres --tenant local --tools-config tools.json p4 drain reconcile
python -m ai_native_system --postgres --tenant local --tools-config tools.json p4 drain evidence \
  --proof-dir /secure/proofs --attest-key /secure/attester-private.pem --attest-public-key /secure/attester-public.pem
python -m ai_native_system --postgres --tenant local p4 proof OP_ID source_receipt --proof-dir /secure/proofs
~~~

越权或过期授权仍由 P3 核验。参考源支持同一源事务内多目标版本检查和终态签名回执。实际长周期异步源的受理协议在源联调时验证。现有应用执行入口每步仍发出一个状态变更目标，多个步骤通过顺序任务合成。外部任意代码、跨源分布式事务和自动补偿留在相应的部署及业务设计范围。

## 验收与复跑

~~~bash
uv sync --locked --extra postgres --extra integrations --python 3.12 --no-build
uv run --locked --extra postgres --extra integrations --python 3.12 python -B deployment/local-postgres/verify_p4.py
~~~

2026-11-17 验收通过 23 项 P4 PostgreSQL 测试、105 项既有 PostgreSQL 回归和 125 项常规测试。P4 专项共 35 项，其中 7 项源数据库、9 项持久对账与证据、7 项端到端，以及 12 项 SDK、签名与文件测试。

同一个临时 PostgreSQL 18.7 实例建立框架与参考源两个独立数据库，两边使用各自的事务和身份。参考源通过独立 MCP 进程和真实回环网络提供服务。两个独立的合成同步来源用于演练事实迁移，引入第二个不可原子锁定的执行依赖时转人工。生产架构继续使用 PostgreSQL 做框架主库，实际业务源沿用自身存储和执行权限。

关键注入覆盖隐藏或变更的关系成员、源记录版本竞争、源进程提交后退出、对账暂时不可用、伪造回执、独立签名故障、证据文件丢失、部分成功、到达上限后的只读核对，以及恢复到派发前备份。恢复到旧备份前仍需按 P3 操作更新库外恢复纪元，并同步更新受影响源服务接受的签名纪元。对签名来源、读取身份、版本维护、写入条件和容量的企业联调归 P9。
