---
name: ida-analysis
description: 使用 ida-mcp-stdio 分析用户指定的二进制或 IDA 数据库；处理缺少 Python 环境或后端配置的启动错误。
---

[English](SKILL.en.md)

1. 查看实际工具定义，用数据库操作打开目标。保留返回的 `instance_id`，在后续调用中明确指定数据库。
2. 编写 IDAPython 前查询 `reference`，将相关查询合并到 `execute_python` 中。只返回分析需要的结构化结果，较大列表分页读取。
3. 报告发现时标注数据库和地址，分别说明直接观察和推断。证据不足时继续查询。

启动失败时查看 stderr：缺少环境就把项目安装到私有 Python 3.10+ venv，并将解释器绝对路径设为 `IDA_MCP_STDIO_PYTHON`。IDA 9.2 使用 native；Nexus 需要 IDA 9.4+、Python 3.11+ 和对应 extra。

同一服务选择插件注册或直接 MCP 配置其中一种方式。转录 hooks 按客户端的正常机制审阅。目标修改和执行应在用户授权范围内。
