# P8 通用应用、SDK 与运行台验收

| 参考应用 | 可交付操作 | 复用的能力 |
| --- | --- | --- |
| 权限内问答 | 从获准文档检索相关片段，并返回原文和可定位引用 | 发布、P2 文档权限和委派、P5 模型路由、P7 检索 |
| 指定范围依据摘编 | 显式选择文档，生成固定 Markdown 版式的依据摘编 | 同一检索、模型预算和引用复查，模型负责选择片段 |
| 版本约束的对象操作 | 按对象版本提交任务，获得人工审批和 OpenWorkProof 授权后执行 | 同一 Runtime、事实和规则、工具、结果回执及证据 |

三类应用由 [应用目录](../fixtures/p8-applications.json) 与 [Registry 样例](../fixtures/p8-registry.json) 登记。验收沿用 P2b 的两个合成事实源、现有连接器和规则。应用适配可通过新增目录与发布定义接入。各发布绑定应用、模型、知识范围、Ontology 与动作。

## 配置和运行

1. 将 PostgreSQL 迁移至 `0020_application_delivery`，配置既有企业身份、运行角色和模型路由。可参考 [模型样例](../fixtures/p8-models.example.json)。
2. 使用应用目录与 Registry 草拟各自发布。问答与摘编授予 `read` 和 `run` 应用权限及相应发布、文档、模型和索引权限。受控动作使用 OpenWorkProof profile、绑定已发布规则，并授予提交和任务级访问。请求者与独立审批者的任务权限由原控制角色配置。
3. 需要在运行台操作发布时，为专用账号配置 `AI_NATIVE_POSTGRES_CONTROL_DSN`，并为对应审定身份授予 `manage / app / 应用`。带签名校验的证据视图从 `AI_NATIVE_P8_ATTESTATION_KEYS` 读取按租户配置的公钥文件列表。可配置 `AI_NATIVE_P4_DELIVERY_DSN`，让人工对账在原持久队列上领取一次只读回执查询。

```bash
python -m ai_native_system --postgres --registry fixtures/p8-registry.json \
  --models "$model_config" serve --application-catalog fixtures/p8-applications.json
python -m ai_native_system --postgres p8 --url http://127.0.0.1:8789 apps
```

打开 `http://127.0.0.1:8789/console/`。工作区包含应用启动、任务进度与审批、回执与证据下载、发布与影响分析，以及事实覆盖、冲突和新鲜度。审批显示当前提议摘要和实际获准的参数、资源范围和规则版本。图任务展示已设定的截止时间。人工接管的接受和拒绝绑定同一份未知结果快照，并独立显示于源端结果和密码学验签状态。

SDK `ai_native_system.client.Client` 使用显式 Bearer 凭据。`submit` 和受控应用请求以请求键恢复同一任务，`approve` 和 `reject` 绑定提议摘要，`events` 使用任务内提交序号分页。事件页与证据导出只包含权限许可的摘要、运行状态和核验信息。SDK 调用方可根据传输错误的 `outcome_unknown` 使用同一个请求键或提议摘要显式重试。

```python
from ai_native_system.client import Client

client = Client(url, token)
task = client.run_application("controlled-action", {
    "object_id": "asset-1", "expected_version": 1,
    "release_digest": release_digest, "request_key": "verify-asset-1",
})
page = client.events(task["id"], limit=20)
```

## 验收范围

真实 PostgreSQL 18.7 和 pgvector 0.8.7。参考应用使用锁定的 LiteLLM SDK 和回环模型端。控制台通过 Chrome 测试，从提交、切换到独立审批身份、校验提议摘要，一直到签名授权后的执行及证据下载。任务界面使用测试身份映射，既有企业身份连接器单独回归验证。正式企业语料与身份服务的验收保留到 P9。

| 验证方式 | 结果 |
| --- | --- |
| `verify_p8.py --browser` | 16 项通过，含 7 项 HTTP SDK 测试、3 项应用复用测试和 6 项真实数据库控制台测试 |
| `verify_migration.py` | 7 项迁移回归通过 |
| `verify_p2a.py` | 22 项企业身份、发布和权限回归通过 |

审批测试在 PostgreSQL 已记录决定后主动断开 HTTP 响应，显式重复同一摘要可确认原决定，随后只发生一次授权消费和业务效果。分页测试让较小全局 ID 的事件晚于较大 ID 提交，任务内游标仍能读到后续事件。撤销发布并移除现行 Registry 定义后，原任务、回执摘要和验证状态仍可由获准身份查询。

```bash
python -B deployment/local-postgres/verify_p8.py --browser
```

浏览器验收使用本机 Chrome 和 Playwright。可通过 `P8_PLAYWRIGHT_MODULE` 指定安装位置，如需切换已配置浏览器，可使用 `P8_BROWSER_CHANNEL`。
