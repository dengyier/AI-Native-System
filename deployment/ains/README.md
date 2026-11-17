# AINS

AINS installs the corresponding version of [AI Native System](https://github.com/dengyier/AI-Native-System), a framework for governed enterprise AI workflows, with shorter command names.

```sh
pip install ains
ains --help
```

For MCP clients, install the optional dependencies and start `ains-mcp` over stdio. Set `AI_NATIVE_API_URL` and `AI_NATIVE_API_TOKEN` to connect to an existing AI Native System deployment. The server reads applications and task status using the configured identity.

```sh
pip install "ains[mcp]"
```

Copyright © 2026 dengyier. Personal learning and other noncommercial use are free under the [AI Native System Noncommercial License v1.3](https://github.com/dengyier/AI-Native-System/blob/main/LICENSE.md). Commercial use requires separate written permission from dengyier.
