# FDE 方法卡受控写操作的 MCP 适配

本模块将 AINS **已经集成的 OpenWorkProof 企业动作链**连接到 FDE 独立源执行进程。它不新增人工审批、授权账本或签名中心，不直接连接 FDE 数据库，也不把操作包装成 OpenWorkProof 原生代码交付流程。

## 连接和身份

```text
AINS任务 → 提议摘要 → 独立人工决定 → 现有OWP授权/消费
  → 官方MCP Streamable HTTP → Python源桥接
  → FDE独立源执行进程 → MySQL条件执行/源证据
  → 签名源回执 → 原AINS对账与证据链
```

只有一个人工决定：AINS 中绑定提议摘要的独立人类审批。FDE 的提交记录仅表示请求者希望审核某份指定版本，不是第二份人工批准。FDE 源端仍须重新核对当前请求者、审批者、卡片版本及提交记录、撤销和有效期。

桥接模块使用官方 `mcp==2.3.0`，沿现有 `mcp-sdk-http` / `source-write/v1` 传输。执行和查询两种 MCP 凭据不同，转发到 Node 的两种内部凭据也分别配置，总共四个不同值。凭据只从独立环境变量读取，不能把 MCP 凭据当作 Node 凭据转发，普通用户 JWT 也不能使用这些接口。

独立启动示例：

```text
python -B -m ai_native_system.fdesage_source --config /controlled/source.json
```

默认的 AINS API、FDE 用户服务均不会自动启动这个进程。配置模板在 `deployment/pilots/fdesage_method_card/source.example.json`。源桥接仅监听 `127.0.0.1`；生产如需跨主机接入，应由部署方提供经核验的 HTTPS 边界，不将此回环监听称为网络隔离证明。

## 唯一业务动作与输入

固定命名空间/tenant 为 `fdesage-ops`，source 为 `fdesage-method-cards`。动作是 `verify_method_card`，动作版本与工具版本均为字符串 `"1"`，工具登记名为 `method-card.verify`，执行身份为 `fde-method-executor`。

| MCP 工具 | 输入对象 | Node 路径 |
|---|---|---|
| `apply_fdesage_method_card` | `{operation, authorization}` | `POST /api/integrations/ains/method-cards/execute` |
| `lookup_fdesage_method_card` | `{operation}` | `POST /api/integrations/ains/method-cards/lookup` |

`operation` 沿用 AINS 既有 `validate_operation`。唯一目标为 `method_card` / `method-card:<id>`，原生记录为 `method_cards` / 正十进制 ID，状态仅允许 `draft → verified`。源原生版本表达为 `revision:<n>:sha256:<contentDigest>`，绑定实际修订和完整内容；AINS 本地对象版本是独立的正整数，不能混为同一版本。

source_conditions 中恰有一个提交记录 guard，type 为 `method_card_submissions`，id 是该提交 UUID，expected_version 为提交记录摘要。源端必须根据实际行核验它；桥接结构检查不能代替数据库核权、CAS 或防重放。

### 重复申请、事实和规则版本

FDE 创建一份新申请时，会原子绑定方法卡的 `verification_intent_id`，并推进原生卡片修订。这个指针属于完整内容摘要，故更换申请会同时改变原生版本令牌；重复同一 requestId 不再次推进。AINS 的应用、ontology、工具和规则保持静态，数据变化通过事实读集和原生版本绑定，不为每次申请发布一套新规则。

FDE `sourceSnapshot` 声明固定的每卡流 `method-card-review:<cardId>`，范围恰为该卡和当前不可变申请载荷两条记录；snapshotRevision 使用真实卡片修订，bookmark 是源生成的申请摘要，capturedAt 是原提交的数据库 UTC 时间。申请载荷的 payloadVersion=1 只表示这份不可变载荷，和卡片修订、当前撤销状态分别表达。

`fdesage_method_card.intent_snapshot()` 严格校验此声明，再用既有 FactSync 导入。内部 COMPLETE 仅表示这两条明确声明的当前视图记录齐备，不能宣称全库覆盖、实时事实或连续 CDC。新申请沿相同每卡流导入；旧申请退出“当前两条记录”的视图，但历史源行保留，不能把视图缺席说成物理删除。旧快照和旧审批不能覆盖新的卡片修订。

原生申请载荷的 recorded 状态不代表当前许可。源端在拿齐锁后仍重新检查撤销、期限、账号、版本和向量。对完整可信且仍在有效期内、但申请已撤销的晚到授权，源端保留原 operation 的签名条件拒绝，AINS 以失败终态对账，卡片不变；不能伪造“取消成功”或永久留在未知状态。错签名、错范围、过期和当前账号失效仍拒绝进入执行。

工具注册通过 `tool_schema_pins()` 得到 SDK 实际生成的输入/输出 schema 摘要。不要手写“相似”schema 或关闭 pin 校验。模板工具登记在 `deployment/pilots/fdesage_method_card/tools.example.json`；源回执公钥应来自独立可信配置，不能信任回执自带公钥。

## 回执、故障与恢复

Node 成功响应直接返回既有 `ai-native-action/source-receipt/v0.1` 签名 envelope，不增加 success/result 包装。桥接和原 AINS 链均核验签名、可信源、原 operation/request_hash、全部且仅限授权目标、前后源版本，以及执行时的 authorization_digest。

执行只接受 `succeeded` 或 `rejected`。`not_found` 仅用于查询确实不存在的操作。源事务已提交但签名待恢复时，Node 返回 503，桥接报告 MCP 工具错误，AINS 保留未知/对账状态；不得把它签成 not_found、自动换 operation 或重新执行。

桥接每次只发出一次请求，不跟随重定向，不使用环境代理；固定源 origin，非本机回环必须使用 HTTPS。整个异步网络调用受总预算限制，请求和回执均限 256 KiB。第三方网络异常、响应正文和凭据不进入工具错误文本。网络或验签失败不等于已证明源端没有产生业务效果，只能查询同一 operation。

## 字节和版本兼容

`fixtures/pilots/fdesage-method-card/golden-profile.json` 提供固定合成向量：独立测试用授权/源 Ed25519 密钥、操作请求、授权、三类源回执及准确签名字节。**其中私钥是公开测试夹具，绝不能进入生产信任配置。** Node 与 Python 必须逐字节匹配此夹具。它是企业动作契约测试数据，不是原生 Acceptance Bundle。

三种摘要规则不要混用：

1. 旧 operation request_hash 使用 `storage.digest`（UTF-8、ensure_ascii=False、按键排序）。
2. 某些 AINS 规则/参数摘要使用其已有 canonical_json/profile_digest。
3. OWP 企业签名使用固定前缀加 OpenWorkProof 1.6.1 `canonical_bytes` 的 RFC8785 结果；`key_id` 是原始32字节 Ed25519 公钥的 SHA-256 指纹。

## 验收边界

`tests/test_fdesage_source.py` 覆盖黄金向量、真实回环 HTTP、官方 MCP 双跳凭据隔离、待签/错误不重发、回执篡改、错误来源与超时。它的源 HTTP 返回为合成签名回执，不能代替实际 MySQL 效果、并发、撤销和进程崩溃恢复验收。

`deployment/pilots/fdesage_method_card/verify_joint.py` 是**隔离验收工具**：新建自己的测试库和角色，启动受限 FDE 用户 API、实际独立 Node 源进程和官方 MCP 桥接，复用真实 PostgreSQL AINS runtime、发布、规则、审批、授权消费和投递对账。它使用合成咨询模型和合成独立人工决定，绝不能作为生产审批人或自动批准器部署。运行所需私有配置、数据库密码和签名私钥不进入公共证据；输出目录的 private 子目录必须排除。

联合场景覆盖批准执行、人工拒绝、源提交成功后响应丢失的查回、同卡后续申请使旧审批失效并保持同一发布、源端撤销后的晚到条件拒绝。它不证明方法卡专业质量或真实人工验收。普通数据库角色旁路、真实数据库恢复及生产发布仍以对应的独立验收为准，生产默认关闭。
