# AI Native System Python SDK

通过 HTTP 访问已部署的 AI Native System 应用 API。SDK 使用 Python 3.11–3.15 的标准库。

## 安装

从 [SDK 发布页](https://github.com/dengyier/AI-Native-System/releases/tag/sdk-v0.1.0) 下载 wheel 后安装。

```bash
python -m pip install ai_native_system_sdk-0.1.0-py3-none-any.whl
```

检出源码后，也可在仓库根目录执行 `python -m pip install ./ai_native_sdk`。

## 连接应用

把服务地址和访问令牌分别配置为 `AI_NATIVE_API_URL` 和 `AI_NATIVE_API_TOKEN`。远端服务使用 HTTPS，本机回环服务可使用 HTTP。用部署方授予身份的令牌查询当前可访问的应用。

```python
import os

from ai_native_sdk import Client

client = Client(os.environ["AI_NATIVE_API_URL"], os.environ["AI_NATIVE_API_TOKEN"])
print(client.applications())
```

完整示例见 [list_applications.py](https://github.com/dengyier/AI-Native-System/blob/sdk-v0.1.0/ai_native_sdk/examples/list_applications.py)，部署和权限配置见 [框架 README](https://github.com/dengyier/AI-Native-System#接入应用)。

## 许可

本 SDK 及随附示例采用 MIT 许可。框架部署与商业使用适用 [主框架许可](https://github.com/dengyier/AI-Native-System/blob/main/LICENSE.md)。
