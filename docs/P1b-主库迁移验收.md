# P1b PostgreSQL 主库与迁移验收

框架支持显式选择 PostgreSQL 或 SQLite。旧任务与旧配置可沿用原有 ID、配置指纹、审批摘要和远端请求摘要。PostgreSQL 验收使用固定的 18.7 镜像和本地数据。[P0 环境基线](P0-环境验收.md) · [开发计划](superpowers/plans/2026-11-16-six-layer-owp-integration.md)

2026-11-17 验收结果为 88 项常规测试通过、32 项 PostgreSQL 专项测试通过。常规发现入口会跳过需要 PostgreSQL 的测试，四个临时库脚本分别执行这些专项。资源告警诊断中连接告警为零。

## 复跑

在项目根目录运行。每个脚本创建独立临时 PostgreSQL，运行完成后销毁该验证实例。

```bash
uv sync --locked --extra postgres --python 3.12 --no-build
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_migration.py
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_runtime.py
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_facts.py
```

## 已验收

| 验收项目 | 可观察结果 |
| --- | --- |
| 显式 schema 迁移 | 迁移角色执行带校验摘要的 SQL 版本。运行角色可使用数据库，正常运行不执行 DDL |
| 离线 SQLite 导入 | 7 项迁移测试通过。任务、知识历史、审批、未知远端操作、回执和原始文本精确保留。事件序号可接续。相同快照重跑返回已有结果，差异或约束失败在单一事务内拒绝 |
| PostgreSQL Runtime | 11 项运行回归通过。两个连接池并发提交命中同一任务，重复执行只记一次效果。并发同版本更新只有一个成功，过期领取方的迟到结果丢弃。连接池和锁等待受限，事务回滚和 Unicode 检索正确，CLI 可读取持久任务 |
| 远端回执与迁移接管 | 独立 HTTP fixture 提交成功后丢失响应。SQLite 任务导入 PostgreSQL 后只按原操作 ID 和摘要查询，回执确认业务写入一次 |
| 单实例恢复 | 使用 `pg_dump` 和 `pg_restore` 恢复框架 schema，应用读取恢复的任务、事件和未知操作。推进时只查询回执，未重新派发该操作 |
| 语义存储 | 9 项测试验证本体版本与摘要、身份映射历史、事实断言和双时间、来源事件去重、事实投影、游标前序比较和待投递失效记录 |
| 运行生命周期 | 存活探针与存储就绪探针可区分进程和数据库状态。排空期拒绝新写入请求，等待已接纳请求至配置期限。CLI 指标标记过期领取、待对账数量和最早时间 |

持久化骨架使用同租户事务锁保护当前执行器的读改写。跨租户可并行运行，迁移与执行互斥，连接池在独立的 PostgreSQL 运行角色下启动。运行租约超期后可接管，P5/P6 承接长调用续租与任务总期限。P2b 实现来源选择与原子同步，P3 加入 OWP 授权与撤权复验，生产恢复和外部效果核对继续由各自阶段验收。[运行适配](../ai_native_system/adapters/postgres_runtime.py) · [迁移与导入](../ai_native_system/adapters/postgres.py) · [语义存储](../ai_native_system/adapters/postgres_facts.py)

## 在自己的测试库启用

1. 准备独立测试数据库。由数据库管理员创建 `ai_native` schema，设置迁移角色为所有者。运行角色使用另一个登录，部署方按表授予运行所需的读取和写入权限，以及事件序列使用权限。迁移版本表授予运行角色只读权限，导入记录由迁移角色管理。[角色测试](../tests/test_postgres_storage.py)
2. 在进程环境提供 `AI_NATIVE_POSTGRES_MIGRATION_DSN`，使用迁移角色执行 `python -m ai_native_system --postgres migrate`。
3. 需要导入时，停止旧 SQLite 应用写入并制作一致备份。运行 `python -m ai_native_system --postgres import-sqlite /path/to/snapshot.sqlite`。核对返回的各表行数和快照摘要，再切换单一写入方。导入在只读方式下读取 SQLite。对已有不同数据的目标库，导入会拒绝。
4. 在运行进程环境提供运行角色的 `AI_NATIVE_POSTGRES_DSN`，用 `--postgres` 替代原 CLI 的 `--db`。可用 `inspect` 查看迁入任务。`init` 用于向独立测试库写入示例目录，导入已有数据时直接核对迁入任务。

应用切换由使用方在指定环境中执行。迁移后恢复生产写入前应核对事实来源、授权与已经发生的外部效果。P3 与 P9 的恢复测试覆盖这些后续要求。

## P2a 租户隔离进展

本节记录 P2a 首批 `0004_tenant_rls` 隔离验收。受信服务把认证绑定的租户写入当前事务，18 张现有业务表启用 PostgreSQL 行级权限。任务子表通过父任务限制范围。没有租户上下文时缺省不可见。5 项真实库测试覆盖跨租户读写、连接复用及回滚后的上下文清除。运行角色就绪检查拒绝直接或可通过 `SET ROLE` 获得的绕过权限。HTTP 任务请求仍由 Bearer 配置绑定身份。旧应用从当前配置移除后，请求者仍能读取已存历史，缺少兼容配置的旧动作会停止。[隔离策略](../ai_native_system/migrations/0004_tenant_rls.sql) · [PostgreSQL 行级安全文档](https://www.postgresql.org/docs/18/ddl-rowsecurity.html)

```bash
uv run --locked --extra postgres --python 3.12 python -B deployment/local-postgres/verify_tenant_isolation.py
```

迁移账号保留离线导入用途。运行数据库凭据由受信服务持有，数据库侧租户过滤以该服务提供的 `tenant` 为准。后续的企业身份、细粒度权限与不可变发布记录见 [P2a 验收](P2a-企业身份权限与发布验收.md)。pgvector 知识权限由 P7 验收。
