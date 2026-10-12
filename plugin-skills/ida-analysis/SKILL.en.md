---
name: ida-analysis
description: Analyze user-selected binaries or IDA databases through ida-mcp-stdio; handle startup errors caused by missing Python or backend configuration.
---

[中文](SKILL.md)

1. Read the actual tool definitions and open the target through database operations. Keep the returned `instance_id` and explicitly select it on later calls.
2. Query `reference` before writing IDAPython. Combine related queries in `execute_python`, return the facts needed for analysis and paginate large listings.
3. Identify the database and addresses in findings. Separate direct observations from inferences and query further when evidence is insufficient.

For startup failures, read stderr. If the environment is missing, install this project in a private Python 3.10+ venv and set `IDA_MCP_STDIO_PYTHON` to its absolute interpreter path. Use native for IDA 9.2. Nexus needs IDA 9.4+, Python 3.11+ and its extra.

Use either plugin registration or direct MCP configuration for the same server. Review transcript hooks through the client's normal controls. Keep target modifications and execution within the user's authorization.
