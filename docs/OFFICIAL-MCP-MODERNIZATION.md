# 0.3 / 0.4 迁移说明

[English](OFFICIAL-MCP-MODERNIZATION.en.md)

## 默认行为

- 服务默认 `stdio`、`native`、`compact`。IDA 从原服务进程移到独立的 idalib worker，每个数据库一个进程，父进程处理协议。
- `compact` 工具发现返回六个入口；使用 `--tool-profile legacy` 恢复旧工具列表，`full` 展示所有注册工具。
- Python `IDAMCPClient` 默认仍为 `legacy`，已有 helper 调用保留。
- 打开新数据库保留旧目标，不再自动关闭；批量任务应主动释放已完成的目标。
- `open_database` 支持新参数 `path`，保留 `binary_path`；返回 `instance_id`。跨库执行代码时，明确传入该 ID。

## 新能力

`execute_python` 提供组合分析、持久上下文、临时作用域、顶层 await 和结构化输出；`reference` 从本机 helper / Domain 源码查询 API。大结果保存为完整 artifact，Python 客户端自动读取所有分页。会话 JSONL 和 HTML 导出按需开启。

这些接口借鉴[官方 Hex-Rays MCP](https://github.com/HexRaysSA/ida-mcp)。本项目未复现官方 token 节省 benchmark，不提供性能提升比例。

## 0.4 补充

- `reference` 索引已安装 Domain 包的全部公开 API，返回版本和完整可运行示例。API 与示例分别分页，需要时返回源码。
- Nexus 的 `--idle-timeout` 释放空闲租约，默认关闭。最后一个受管理的无头 owner 保存后退出；其他客户端的租约和 GUI 实例继续保留。生命周期事件写入 JSONL，断连警告通过 MCP 日志通知发送。
- `dashboard` 展示多个会话及明确关联的客户端转录，token 和费用采用记录值。`logs` 导出原始记录、关联转录、结果文件和 ZIP 清单。
- `install` 按 Codex、Claude Code / Desktop、OpenCode、ZCode 格式写配置并备份；`update` 升级 venv 后刷新配置。可选 hooks 关联 Claude Code 和支持该能力的 Codex 转录，Codex 需在 `/hooks` 审阅信任。
- [对比示例](../examples/compare_tool_profiles.py) 测量等价 legacy / compact 分析，并统计工具发现的开销。它测量的是消息体和 token，未复现官方智能体任务基准。

## 后端选择

| 需求 | 选择 |
| --- | --- |
| 始终纯无头、IDA 9.2 | `--backend native` |
| 始终纯无头、IDA 9.4+ | `--backend native` |
| 9.4+ GUI 或跨客户端共享 | 安装 Nexus extra，使用 `--backend nexus` |

Nexus 会复用匹配的 GUI 实例，找不到匹配实例时启动无头 worker。`close_database(save=False)` 和 `force_reanalyze` 仅 native 支持。Nexus 的租约、事件与崩溃恢复来自官方库。

## 更新客户端

配置改为当前安装环境的绝对 Python 路径，执行 `-u -m ida_mcp_stdio`；避免同名全局安装指向其他仓库。分析样本按会话调用 `open_database` 打开，避免固定在全局启动参数中。

旧会话需重新加载 MCP；Claude Desktop 需重启。配置格式见[客户端配置](MCP-CLIENT-SETUP.md)，生命周期差异见[数据库管理](DATABASE-MANAGEMENT.md)。
