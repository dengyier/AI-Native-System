# P3 OpenWorkProof 授权与执行验收

## 已实现

| 能力 | 框架行为 |
| --- | --- |
| 企业动作 profile | 固定 OpenWorkProof 1.6.1，复用规范编码、Ed25519 和公钥指纹。企业授权与效果证据各有独立 Schema 和签名域。任务、动作实例、操作、主体、审批和结果通过各自字段绑定。 |
| 语义绑定 | 签名覆盖不可变发布、本体与规则版本、规范对象、实际参数、工具身份和目的地、字段与关系范围、委派、人工审批和事实读取集。读取证明覆盖源游标、关系集合成员与版本、证据和新鲜度。 |
| 统一检查点 | 启用 OpenWorkProof 的动作必须有已绑定的 P2b 规则与独立人工审批。CLI、HTTP 和后台 worker 使用同一运行器，使用主库复查当前授权、ACL、事实和摘要。规则读取使用的附加字段和关系也必须在主体范围内。签名材料与事实证明明细留在受信服务。 |
| 持久防重放 | 授权、撤销、nonce 和原操作记录由 PostgreSQL 约束。授权不足返回需要人工处理，授权失效、撤销或作用域变化阻断执行。本地效果与 nonce 在一个事务提交。 |
| 远端恢复 | 原始请求和消费记录在网络调用前提交。已派发的原操作可按固定目的地和请求摘要查询回执。撤权、备份恢复或下游返回 `not_found` 不会触发重发。 |
| 证据补签 | 业务效果与待签证据一起提交。签名暂时不可用时，可以补签原记录。签名和重试都不再次调用业务工具。可用独立公钥离线验证效果摘要。 |

签名和规范字节见 [企业 profile](../schemas/ai-native-action-v0.1/README.md)。旧版发布保留旧入口。存量租户启用 P3 时由库外公钥配置和数据库租户标志拒绝向旧版执行模式回退。P3 覆盖现有事务型状态工具及已登记的 HTTP/MCP 单动作。通用工具执行和源侧条件写归 P4。

## 启用

1. 安装锁定的 PostgreSQL 与集成依赖，确认已应用 `0011_owp_evidence` 及后续迁移。所有 PostgreSQL 运行角色新增 `owp_enforced_tenants` 的 SELECT。启用 P3 的运行角色另外读取授权台账与证据表，只对任务准入、nonce 消费与待签证据表追加记录。
2. 在独立于 PostgreSQL 备份的可信部署配置中设置 `AI_NATIVE_OWP_TRUST`，值为 JSON 文件路径。每个租户配置一个恢复纪元和授权验签公钥 PEM 路径数组。运行器、注册端和后台 worker 使用同一份当前公钥配置。私钥仅由签发端持有。
3. 创建新发布草稿时指定 `--owp-profile ai-native-action/v0.1` 和实际的 `--policy-version`。在草稿上用 `govern bind-rule` 绑定所需规则，配置对象、字段、关系、工具、版本和审批权限。P3 状态工具会写状态和版本，执行主体需两个精确的元数据写权限。发布后选用新版本。
4. 如需整个租户强制启用，在处理完未决远端操作后，用控制角色执行 `owp enforce`。控制角色维护撤权及强制启用状态。按照既有流程提交、推进、独立审批，再生成并注册签名授权。

信任文件示例

~~~json
{
  "local": {
    "epoch": "staging-20261117-01",
    "public_keys": ["/secure/authority-public.pem"]
  }
}
~~~

各命令所用的角色

| 命令 | 权限与材料 |
| --- | --- |
| `owp request` | 应用运行身份读取当前审批与事实，生成准确的签名请求。模型和工具的配置与运行器一致。 |
| `owp sign` | 离线签发端使用授权私钥，给请求加入唯一 nonce 和有限有效期，默认 120 秒。 |
| `owp register` | `AI_NATIVE_OWP_ISSUER_DSN` 角色读取当前任务、权限与事实，追加已验签授权。命令也通过 `AI_NATIVE_POSTGRES_DSN` 验证部署运行角色。注册与消费都会校验当前范围。 |
| `owp enforce`、`owp revoke` | 控制角色追加租户启用或撤销记录。运行账号不能签发、撤权或删除既有台账。 |
| `owp pending`、`owp attest` | 独立证据角色 `AI_NATIVE_OWP_EVIDENCE_DSN` 读取已提交证据，更新交付列。签发效果证据使用独立验签配置。 |
| `owp verify-evidence` | 传入托管的证据公钥及 `attest` 响应的 `proof` 对象，离线验证。 |

~~~bash
python -m ai_native_system --postgres --tenant local owp request TASK_ID > request.json
python -m ai_native_system --postgres owp sign request.json --key-file /secure/authority-private.pem > authorization.json
python -m ai_native_system --postgres --tenant local owp register authorization.json
python -m ai_native_system --postgres --tenant local advance TASK_ID
~~~

## 撤权与恢复

同租户的授权、撤权、事实变化和本地效果使用同一写锁。本地效果按提交事务排序。远端派发以原请求和 nonce 提交为界；此后撤权只能阻止新的执行，已发出的请求仍可查询原回执。因授权失效而关闭的操作须用新任务重新审批，存在未知外部效果时先核对原操作。证据中的 `remote_receipt_observed` 表示执行服务观察到回执，源签回执与源侧版本原子校验已在参考服务验收。[P4 验收](P4-MCP条件写入与证据闭环验收.md)

恢复到较旧备份前停止旧运行进程。为相应租户在库外更新恢复纪元，并让所有运行与注册进程使用新配置后再开放流量。恢复后，旧纪元任务无法继续调用模型、获得新授权或派发写入。已有消费记录的远端操作可以按原绑定对账。备份中只有待发送意图时保留人工核对状态，原系统是否产生效果需要另行确认。测试覆盖真正的 `pg_dump` 和恢复。验收依赖库外纪元切换；生产环境的自动化恢复编排和隔离留待 P9。

## 复跑

~~~bash
uv sync --locked --extra postgres --extra integrations --python 3.12 --no-build
uv run --locked --extra postgres --extra integrations --python 3.12 python -B deployment/local-postgres/verify_p3.py
~~~

2026-11-17 验收通过 27 项 P3 PostgreSQL 专项、78 项既有 PostgreSQL 回归和 113 项常规测试。P3 专项包括 7 项授权台账、5 项证据与 15 项接入流程。

以 PostgreSQL 18.7 主库、真实 OpenWorkProof 固定版本、独立进程、真实回环网络和本地合成来源验收。权限执行和签名隔离覆盖框架进程与 PostgreSQL 角色。操作系统和网络层防绕过、企业密钥托管、真实外部系统的执行语义在后续阶段验证。
