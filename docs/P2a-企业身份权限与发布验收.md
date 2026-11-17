# P2a 企业身份、资源权限与发布验收

## 已实现

| 能力 | 框架行为 |
| --- | --- |
| 企业账号、服务和委派 | 服务经 HTTPS 验证 OAuth 访问令牌，从显式绑定取得租户及主体。委派需同时满足用户、服务和委派的权限，使用时复查主体状态、时间窗和撤销。请求正文无法覆盖身份。 |
| 资源授权 | 默认拒绝。对象、属性、状态与版本、关系、文档、动作、工具版本、任务、发布和证据分别授权。审批需独立人类账号、当前可读的审批材料和准确的提议摘要。 |
| 语义查询 | `POST /v1/query` 支持类型、ID、等值条件、关系遍历、可见集计数、动作声明发现和解释。含 `application` 时需读取应用及选中的发布，按其 Ontology 查询。省略此项使用进程加载的 Registry。过滤与计数最多检查 200 个已授权候选，返回最多 100 个对象，关系最多 3 跳，响应限 256 KiB，查询应用预算与单语句上限为 3 秒。 |
| 不可变发布 | 规范 JSON 与 SHA-256 固定应用、提示、动作 Schema、本体和规则、模型路由与回退、工具版本与目的地、映射版本、知识引用策略，以及 OpenWorkProof profile 和策略版本。数据库保护内容不被覆写。 |
| 执行与恢复 | 新任务固定发布摘要。推进、审批和写入前复验权限、依据和发布状态。弃用允许已绑定任务继续，撤回阻断后续执行。切换到仍为已发布的旧版本只影响新任务。已派发操作仍可核对原目的地和原操作摘要。 |
| 兼容性 | SQLite 和未启用企业模式的 PostgreSQL 租户保留旧 Registry 和旧令牌配置。启用后旧任务按任务授权读取历史状态，缺少快照的任务停止新的模型和工具调用。 |

身份验证采用 [OAuth Token Introspection](https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2)。委派读取发行方验证过的 `act.sub` 和项目自定义的 `delegation_id`。后台保存受理时的身份上下文及失效时间，以本地主体禁用、资源撤权、委派撤销或发布撤回停止已受理任务。[OAuth Token Exchange 的 actor 声明](https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1)

## 启用与回滚

1. 在独立测试库用迁移账号执行 `python -m ai_native_system --postgres migrate`，确保已应用 `0008_task_governance` 与后续迁移。数据库及 schema 设置见 [主库验收](P1b-主库迁移验收.md)。
2. 保留运行角色的业务表权限，升级时增加对 `governed_tenants` 的 SELECT。使用企业模式再按下表添加治理权限。设置独立的操作员登录 `AI_NATIVE_POSTGRES_CONTROL_DSN` 和应用运行登录 `AI_NATIVE_POSTGRES_DSN`。运行凭据由受信服务持有，服务设置每笔事务的租户。[PostgreSQL 行级安全](https://www.postgresql.org/docs/18/ddl-rowsecurity.html)
3. 配置用户和服务主体。发布并选用初始快照，配置资源授权，再执行 `govern activate`。切换前先处理旧任务的待对账操作，命令会阻止存在待对账操作的租户切换。
4. 将 `AI_NATIVE_ENTERPRISE_IDENTITY` 设为 JSON，包含 `issuer`、`audience`、`endpoint`、`introspection_client_id`、`introspection_secret_env`、`bindings`，可选 `required_scope`，默认 `ai-native.access`。每条绑定含 `subject`、`client_id`、`tenant`、`actor`。独立服务在 `actor` 和 `service` 填同一主体。受委派服务另外声明本地 `service` 和外部 `external_actor`。密钥从指定环境变量读取。
5. 运行 `python -m ai_native_system --postgres serve`。企业模式使用独立 HTTP 进程配置，旧模式使用 `AI_NATIVE_API_TOKENS`。服务监听回环地址，由部署环境提供外部 TLS 入口。

| 治理表 | 运行角色 | 控制角色 |
| --- | --- | --- |
| `governed_tenants` | SELECT | SELECT、INSERT |
| `enterprise_delegations`、`enterprise_delegation_scopes` | SELECT | SELECT、INSERT。另允许更新委派表的 `revoked_at` |
| `resource_grants` | SELECT | SELECT、INSERT、DELETE |
| `application_releases` | SELECT | SELECT、INSERT |
| `application_release_lifecycle` | SELECT | SELECT、INSERT，UPDATE `status`、`changed_by`、`changed_at`、`migration_ref` |
| `application_release_selections` | SELECT | SELECT、INSERT，UPDATE `digest`、`changed_by`、`changed_at` |
| `task_governance` | SELECT、INSERT，UPDATE `approver_context` | SELECT |

控制角色还需 schema USAGE 和读取迁移版本、主体、任务及远端操作的权限。运行账号可通过角色切换取得治理写权限时，服务拒绝启动。[测试中的角色设置](../tests/test_p2a_workflow.py)

~~~bash
python -m ai_native_system --postgres --tenant local release draft single --actor operator
python -m ai_native_system --postgres --tenant local release impact "$release_digest"
python -m ai_native_system --postgres --tenant local release publish "$release_digest" --actor operator
python -m ai_native_system --postgres --tenant local release select single "$release_digest" --actor operator
python -m ai_native_system --postgres --tenant local govern grant requester submit app single
~~~

`release draft` 可指定本体文件、映射版本和 OpenWorkProof 引用。影响分析列出涉及的数据、动作、规则、索引范围、应用和旧版任务。破坏性发布需要先准备迁移方案，再用 `release publish --migration-ref` 记录方案引用。通过 `release select` 切换发布。旧版模型或工具配置使用 `--release-adapters` 加载，配置以摘要为键，每项的 `models` 或 `tools` 路径相对此文件解析。运行时复核归档适配器与快照是否一致，`release revoke` 可停用包括归档在内的旧版本。

`govern grant` 与 `govern revoke` 接收主体、操作、资源类型和 ID，可用 `--member` 精确指定字段、关系、状态或版本。工具版本资源如 `state.transition@1`，名称组件里的 `%` 和 `@` 分别转义为 `%25`、`%40`。通过 `govern delegate` 载入委派 JSON，其字段为 `actor`、`service`、`delegation_id`、`scopes`、`starts_at`、`expires_at`。scope 是 `[operation, kind, resource_id, member]`，整体资源的 member 为 `null`，时间带时区。通过 `govern revoke-delegation ID` 撤销。

任务发起者需具备应用提交、发布及动作读取集的权限。执行账号需具备动作、工具版本、写入目标及同一读取集的权限。任务创建后，由可信控制方按任务 ID 发放查看、推进、审批或取消权限。审批提交包含 `proposal_digest`，重复提交同一决定会返回已记录结果。证据接口另需 `export/evidence`，返回提议摘要与效果登记状态。事件分页和正式导出工作台归 P8。[工作流验收用例](../tests/test_p2a_workflow.py)

## 复跑

~~~bash
uv sync --locked --extra postgres --python 3.12 --no-build
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_p2a.py
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_migration.py
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_runtime.py
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_facts.py
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_tenant_isolation.py
python3 -B -m unittest discover -s tests
~~~

2026-11-17 使用真实 PostgreSQL 18.7 的临时实例。P2a 专项 22 项、既有 PostgreSQL 回归 32 项、常规回归 96 项通过。专项覆盖 HTTP 请求经 HTTPS 身份服务进入 PostgreSQL、跨租户和隐藏数据拒绝、审批后撤权、发布回滚、模型与工具地址恢复，以及丢失远端响应后的原地址对账。模型、业务对象、身份服务和下游系统为验收 fixture。指定企业身份服务和生产入口留待部署联调。

P2b 的双源事实同步、撤回事件和规则读取集见 [P2b 验收](P2b-双源事实同步与规则验收.md)。P3 接入 OpenWorkProof 实际授权与签名，P7 验证 pgvector 权限检索。P2a 快照固定知识引用策略，各检查点比对实际知识版本与内容摘要。
