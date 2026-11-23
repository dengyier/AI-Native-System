# FDE 军师限定只读接入：捕获记录与授权查询

本批基于 AINS `18545c749989208d3e66510120895f3db6c6ab7f` 的已提交接口新增适配器，使用独立 `dhb-ai-native-system-fde` 分支。原有开发目录中的未提交试点没有复制进来。

## 现有 OpenWorkProof 集成继续复用

AINS 已固定 `openworkproof==1.6.1`，`adapters/owp.py`、`owp_gate.py`、持久授权账本、受控任务及源回执共同承担企业动作治理。本批只读采集不产生动作授权、任务、人工审批或源端业务效果，不再建设另一套审批或签名系统。未来写动作沿该治理链补接 FDE 原生版本、原子执行、撤权及效果回执。

只读快照通过固定 HTTPS 来源或数字回环测试地址读取。它是一次经过身份和范围校验的历史采集记录，**不是 OpenWorkProof 原生 Acceptance Bundle，也不证明任意源端内容或业务结论正确**。

## 本批数据含义

FDE 唯一入口为：

```text
GET /api/integrations/ains/projects/:projectId/documents/:docId/versions/:version/snapshot
```

响应必须精确符合 `fdesage-ains-readonly-snapshot/1`，`application=fdesage`、`contractVersion=1`，固定兼容源发布标识为：

```text
fdesage-backend:31a58ae4d8310a71a0ed3c49971b0a9b6410fb1a+ains-readonly/1
```

该标识用于明确本批契约的代码来源，不声称是当前进程的动态 Git SHA。发布时另行记录实际候选提交。源端更新响应契约必须同步修改双方契约和测试。

- 只采集一个事先登记的工作区、项目、成果文档及正式文档版本。源 ID 为规范正十进制字符串。
- 只保留版本、UTF-8 原文精确字节的 SHA-256、捕获时间及授权观察元数据。不读取正文、咨询对话、截图、草稿或导出文件。AINS 没有拿到正文，因此仅校验摘要格式、版本和关联范围，不能独立重算正文摘要。
- `coverage=selected_object`。`sourceVersion`、`streamPosition`、`cursor` 都保持 `null`，不表示完整快照、原生对象版本、CDC 连续性或实时权威事实。
- `authorization` 绑定明确的 `subjectUserId`、`membershipGeneration`、`delegationId`、`serviceId`。不能根据客户端临时提交的主体或工作区扩大授权。
- 源端权限在源端捕获读取边界判断；捕获后的撤权不改变已经发生的历史观察。重新采集必须再次通过源端当前权限检查。AINS 读取已有捕获记录也必须通过 AINS 自己的当前身份和精确资源授权。

`SnapshotClient` 不跟随重定向、不使用环境代理、拒绝非回环明文 HTTP、用户信息、URL 路径/查询及压缩响应；限制响应 64 KiB，严格拒绝重复 JSON 键及非有限数值。每次网络读取在独立 spawn 辅助进程中完成；父进程持有总预算，覆盖辅助启动、DNS、TLS、响应头及正文。持续滴流也不能刷新总预算。超时后终止辅助进程，必要时强制结束，并用两次各 0.2 秒的有界等待回收；正常操作的返回耗时包含预算及这段短清理时间，不承诺操作系统失去调度时的物理瞬时退出。源凭据不进入辅助进程命令行或错误输出，子进程仅通过有大小限制的管道返回响应字节或固定失败标记，没有遗留网络线程。捕获时间必须落在本次请求区间的五秒时钟误差内。部署前校准双方时钟。传输超时不能被解释为“源端无此对象”。

## 为什么先采用无动作投影

稳定基线中的 `ReleaseSnapshot` 用于绑定可执行应用，需要动作、模型阶段和执行工具。本批没有业务写动作，不能为了满足发布格式而虚构一个动作。

因此本批使用已有 `Registry`、`OntologyRelease`、`objects` 和 `SemanticQuery`：

1. 声明 `fdesage_captured_observation` 类型；`applications={}`、`actions={}`，没有模型或工具使用权限。
2. 按经过严格验证的完整快照规范 JSON 计算摘要，对象 ID 为 `fdesage-observation:<sha256>`。对象只允许追加，重复导入同一快照返回同一 ID；已存在同 ID 而内容不同则报错。
3. 对象 `version=1` 仅表示本地不可变捕获记录版本；正式 FDE 文档版本独立保存在 `document_version`。后一次捕获有不同捕获时间，成为另一条历史记录，不覆盖旧记录。
4. 对象保存 `ontology_digest`、`observation_digest` 和完整的限定元数据。`snapshot_json` 是一个包含全部允许元数据的复合字段，只有获准读取完整捕获记录的审核主体才授予该字段。仅授予少数字段的主体不能获得 `snapshot_json` 权限。
5. 调用现有 `POST /v1/query`，**不传 `application` 或 `authoritative`**。查询按现有身份、对象和字段授权投影，只供获准审核人员核验。

这完成了历史捕获投影和授权查询，尚未完成可执行应用 `ReleaseSnapshot` 的发布选择、原生权威事实查询及连续同步；不能把本批结果写成这些能力已上线。

示例查询：

```json
{
  "object_type": "fdesage_captured_observation",
  "object_id": "fdesage-observation:<capture-sha256>",
  "discover_actions": true
}
```

获准主体的 `objects` 只包含有权字段，`actions` 为空。没有对象权限的主体得到空集合。撤销对象或字段授权后，下次查询重新判断。

## 身份与数据库角色

以下凭据分别保存，不能互换或透传：

| 用途 | 权限与边界 |
|---|---|
| FDE 源采集 token | 独立来源受众、服务及精确委派资源；只能读专用快照，不能登录 AINS |
| AINS 审核 API 身份 | 使用既有 `EnterpriseIdentity`、独立受众及主体映射；只授予指定捕获对象和字段读取权限 |
| AINS 采集导入数据库角色 | 现有迁移完成后，`SELECT` 必要表及 `INSERT` 到 `objects`；无 UPDATE/DELETE、授权、发布、任务、模型、执行或源事实写权限 |
| AINS API 查询数据库角色 | 必要表的 `SELECT`；无业务写、授权、发布或 DDL 权限 |
| 可信配置管理角色 | 独立进行主体登记和 `Policy.grant/revoke`，不随采集 token 下发 |

为所有实际审核主体精确授予 `read/object/<observation-id>` 和允许的 `read/field/<observation-id>/<field>`。需要显示本地记录状态/版本时另授予 metadata 权限。委派身份继续使用现有双主体授权交集及委派范围检查。禁止授予 submit、execute、模型使用、发布或广泛的其他对象权限。

本批的追加约束由导入函数及专用 INSERT-only 角色共同保证。拥有库所有者或其他 `objects` 更新权限的账号仍可能改写记录；不得把本批表述为已实现针对所有数据库账号的防篡改隔离。接入时保留独立采集/API角色，不复用现有宽权限任务执行账号。

## 隔离演练与停止办法

以下命令从这份候选代码的仓库根目录运行；配置示例只包含合成 ID，不能直接用于生产。使用按锁文件准备的 Python 环境和隔离库。导入工具不运行迁移，也不创建角色或授予权限。

```bash
python -m deployment.pilots.fdesage_readonly.capture --config /absolute/test-config.json --output /absolute/new-capture.json
python -m deployment.pilots.fdesage_readonly.import_snapshot --config /absolute/test-config.json --snapshot /absolute/new-capture.json
```

以 `deployment/pilots/fdesage_readonly/config.example.json` 为配置结构。源 token 和导入 DSN 通过各自环境变量提供；不要把凭据写进配置、命令参数、报告或截图。捕获输出使用新建独占文件及 0600 权限，保留已有文件。

采集入口应按上面的 `python -m` 命令或带 `if __name__ == "__main__"` 保护的普通脚本运行，满足标准库 spawn 的启动要求；不要从交互式 stdin 脚本或禁止创建子进程的 daemon worker 调用。每次受控采集有一次进程启动成本，适用于本批低频限定影子采样。

停止采集无需恢复源业务数据：停用采集任务及 FDE 专用路由，撤销采集委派/凭据，停止新导入并撤销审核主体读取权限。已经保存的捕获记录作为历史证据保留或按明确的数据保留方案处理。故障时不要回退调用带补版本/导出副作用的旧接口，也不要伪造 `not_found` 或“校验通过”。

本批不开启生产入口、不注册定时任务、不接入用户回答、不扩展采样范围、不启用方法卡写动作。将来向用户展示需要 FDE 桥接回源核对当前 ACL，不能把历史采集权限当作用户当前权限。

## 验证入口

```bash
python -m unittest discover -s tests -p 'test_fdesage_readonly_capture.py' -v
python -m unittest discover -s tests -p 'test_fdesage_readonly_projection.py' -v
python -m unittest discover -s tests -p 'test_fdesage_readonly_api.py' -v
```

最后一项要求 `AI_NATIVE_P2B_TEST_DSN` 指向明确隔离的 PostgreSQL 测试库及测试管理员身份；会在该库执行既有迁移并创建专用受限测试角色，不要连接生产。未提供 DSN 时按仓库惯例显示未执行，不能把它计为通过。真实 FDE MySQL 源端联调与生产有限样本影子验收另列证据；上述单元测试不能替代上线验收。
