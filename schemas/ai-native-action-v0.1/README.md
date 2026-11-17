# 企业动作授权 0.1

企业授权使用独立的 `ai-native-action/v0.1` profile。授权公开字段见 [authorization.schema.json](authorization.schema.json)，效果证据见 [effect-evidence.json](effect-evidence.json)。校验器同时检查 JSON Schema 表达不了的条件，包括主体属于同一租户、委派关系正确、写操作审批人与请求人独立，以及失效时间晚于签发时间。

## 规范字节与密钥信任

1. 从 envelope 取 `payload`、`signer_key_id`、`signature_alg` 组成 JSON 对象。OpenWorkProof 固定版本为 1.6.1，使用其 `canonical_bytes("capability-grant", body, version="0.1")` 生成规范字节。
2. 在规范字节前加入 ASCII 前缀 `ai-native-action/authorization/v0.1` 和一个 NUL 字节。对完整字节计算 SHA-256 得到小写十六进制 `digest`，使用 Ed25519 签名后输出无填充 base64url。OpenWorkProof 通用授权或回执验证器使用自己的签名域。
3. 调用方从受信配置读取 Ed25519 公钥。使用 OpenWorkProof 的 `key_id` 检查公钥指纹与 envelope 内的 `signer_key_id`。从授权正文取得的公钥不进入信任表。数据库检查 nonce、代次、时间、撤权和作用域。
4. 签名引用实际参数、工具目的地和事实读集的 SHA-256。当前状态变更工具沿用现有 Runtime 参数摘要，远端操作使用原请求的 `request_hash`。事实读集使用事实契约的规范 JSON，计算摘要时移除求值时刻 `as_of`，保留事实版本、有效期、关系集合修订和来源游标等依赖。日期为正整数 Unix 秒，版本可为正整数或非空文本。

`targets`、`reads`、`writes` 的数组次序属于签名内容。发布、规则、证据、动作版本、工具版本及目的地都有各自字段。写授权必须绑定独立人工批准和已验证规则。读取与生成授权的写范围必须为空。

授权规范字节限制为 256 KiB。通过文本接收 envelope 时另预留 1 KiB 给签名元数据。

## 源系统条件写入

[源操作](source-operation.schema.json)绑定实际写目标、源记录映射、预期的原生版本、状态转换和同来源读取守卫。MCP 执行工具接收 `operation` 与 `authorization` 两个字段，查询工具只接收 `operation` 并使用独立认证身份。源系统核验授权后，在业务数据库内原子检查全部版本并提交状态更新和回执。

[源签回执](source-receipt.schema.json)使用 `ai-native-action/source-receipt/v0.1` 加 NUL 的独立 Ed25519 签名域，规范编码使用固定 OpenWorkProof 的 `action-receipt` 基础。源签公钥独立配置。验签同时核对请求和授权摘要，以及返回的目标、旧版本和状态。源系统为每个写目标返回不透明新版本。已知成功或拒绝的去重记录绑定原操作与授权。参考源保留该记录及原签名，`retain_until` 为源承诺的最低保留时刻。签名的 `not_found` 只表示查询当时没有匹配记录。

## 许可

本说明及本目录中的授权、源操作、源签回执和效果证据 JSON Schema 采用 [MIT 许可](LICENSE)。
