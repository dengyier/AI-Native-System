# P2b 双源事实同步与规则验收

## 同步与权威事实

| 能力 | 行为 |
| --- | --- |
| 双源同步 | 每个租户按来源和流分别保存代次、连续位置、游标、记录版本和快照切点。入口使用 `FactSync.snapshot` 和 `FactSync.apply`。原始事件、断言、投影、进度及失效事件在一个 PostgreSQL 写事务中提交。 |
| 去重与恢复 | 同事件 ID 同内容可以重送。异载荷、记录版本碰撞、身份映射冲突及未证明顺序的事件保留在冲突历史。断档会暂停流并标记依据不足。只有通过校验的完整快照可以修复断档和切换代次。旧代次与旧记录版本无法覆盖新状态。 |
| 删除与关系 | 明确删除保存墓碑。仅有可靠切点且证实完整的快照可因缺失推导删除。删除与关系增删更新失效记录和读取证明。部分或过期数据不能证明关系集合为空。 |
| 权威与冲突 | 使用显式来源身份映射和按字段配置的权威来源。配置多个同级权威源时，取值不一致保留各方证据，规则返回依据不足。只有已配置为权威的来源可以成为执行依据。对象属性或状态的人工修正需独立人类身份、字段授权、理由及失效时间。到期后重新按来源权威和新鲜度选择。 |
| 历史追踪 | `Facts.history` 可分别指定业务生效时间与框架得知时间。查询保留源版本、映射修订、断言、人工修正、墓碑、撤回记录和当时的流状态。更新事实时保留历史断言和失效事件。连接器与运行角色不具备删除原始事件、断言与审计历史的权限。部署方管理留存、备份和物理清理。 |

连接器须能给出可验证的快照范围及切点，以及连续的流位置与记录版本。流位置用于判断消费断点，记录版本用于阻止同一对象的旧数据覆盖新值。新鲜度由连接器服务配置，示例默认五分钟。到期或暂停时，历史记录仍可查，依赖该来源的实时判定返回依据不足。

## 接入顺序

1. 确认迁移账号、连接器服务、治理控制和应用运行使用各自的数据库角色。执行 `python -m ai_native_system --postgres migrate`，确认已应用 `0009_fact_sync` 与后续迁移。升级现有 PostgreSQL 运行角色时新增对 `fact_rule_bindings` 的 SELECT。旧 Registry、SQLite 和未绑定事实规则的发布继续走原有行为。
2. 在可信控制事务内用 `Facts.bind_mapping` 将源对象映射到同租户的规范对象。用 `Facts.set_authority` 为字段或关系指定权威源。来源生存状态使用 `$exists`，对象状态使用 `$state`。修改映射和权威配置须给出预期修订、操作者和理由。连接器遇到映射变化时，经完整快照确认后重建该来源的当前投影。
3. 每个受信连接器进程绑定一个租户、来源与流。规范记录使用 `properties`，可含 `state` 和 `relations`。关系的 `target_type` 与 `target_id` 应使用适配器已确认的规范身份。初始快照调用 `snapshot(boundary, records, position=...)`。增量调用 `apply(event, position=..., predecessor=...)`。恢复从最近提交的游标与位置读取，断档后以新的快照 ID 和可信切点重建。上游拒绝当前游标时调用 `invalidate(predecessor)`，用 `status()` 和 `conflicts()` 检查。
4. 在 P2a 发布草稿阶段，用 `govern bind-rule RELEASE_DIGEST RULE_NAME --actor OPERATOR` 将 Ontology 规则作为动作前置条件。已有发布要启用该条件时新建草稿。同一发布的规则绑定一经写入即固定。治理控制负责配置，运行器只能读取。绑定用于新任务的正常推进、审批和执行检查点。

典型权限拆分

| 角色 | P2b 权限 |
| --- | --- |
| 连接器 | 读取显式映射和权威配置，追加原始事件、快照、进度、冲突、事实和待投递事件，更新流状态、游标和投影。为指定源记录操作回流观察。 |
| 治理控制 | 追加身份、权威、规则绑定及授权修正。对相关投影和失效队列拥有必要的写入权限。业务修正与证据撤回还会在框架层按身份和资源授权。 |
| 应用运行 | 读取事实与规则所需信息。远端操作启用回流时，可登记预期状态及更新已校验的回执结论。 |

记录领域权限的控制入口和发布入口仅面向受信进程。具体表权限见 [真实 PostgreSQL 角色与流程](../tests/test_p2b_workflow.py)、[事实与历史用例](../tests/test_fact_store.py)。向量与记忆消费者在 P7 接入当前失效队列。

## 规则与回执

`RuleEvaluator.evaluate` 以已校验的 Ontology 规则为输入，支持状态、类型化比较、关系 any/all 和显式规则依赖。结果为满足、不满足或依据不足。规则按完整的权威资料求值，用户查询仍按 P2a 的可见集合返回。缺失、过期、撤回、来源冲突、断档或部分关系集合均无法作为通过规则的依据。针对关系成员状态的 any/all 是正向条件，完整空集合无法通过该条件。

规则结果返回本体及规则版本、事实和证据修订、源游标、关系成员与集合证明。运行器将证明摘要纳入审批的上下文比较。即使业务值仍相同，读取依据或成员改变也会令原审批停止。权威事实明细与读取集由可信服务处理。P2b 通过绑定规则来约束现有执行器，事实投影保存在事实存储中。

远端工具可在绑定规则时再设置 `--feedback-source SOURCE --feedback-stream STREAM`。运行器将该来源、规范对象、预期状态和操作摘要写入操作台账。源事件提供匹配的 `operation_id` 时自动核对。源事件先到或回执先到均可匹配。来源确认的状态与预期不同会记录冲突。回流只更新事实与核对记录，业务效果继续由原回执路径确认一次。

## 复跑方式

~~~bash
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_p2b.py
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_p2a.py
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_migration.py
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_runtime.py
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_facts.py
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_tenant_isolation.py
python3 -B -m unittest discover -s tests -q
~~~

2026-11-17 在真实 PostgreSQL 18.7 上通过 24 项 P2b 专项及 54 项 PostgreSQL 回归，另通过 103 项常规测试。P2b 专项包括 8 项同步、6 项事实与冲突、4 项规则及 6 项真实执行流程。

真实 PostgreSQL 用例以两个独立的合成来源和本地远端工具验证框架契约。正式源系统的切点、授权、条件写入、保留政策和容量仍需在企业环境验证。OpenWorkProof 执行授权见 [P3 验收](P3-OpenWorkProof授权与执行验收.md)。P4 验证源侧条件写入和完整回执证据。
