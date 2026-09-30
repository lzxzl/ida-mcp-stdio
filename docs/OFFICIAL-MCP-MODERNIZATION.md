# 0.3 迁移说明

## 默认行为

- 服务默认 `stdio`、`native`、`compact`。原来加载 IDA 的服务进程拆成协议父进程和每库一个 idalib worker。
- `compact` 工具发现返回六个入口；使用 `--tool-profile legacy` 恢复旧工具列表，`full` 展示所有注册工具。
- Python `IDAMCPClient` 默认仍为 `legacy`，已有 helper 调用保留。
- 打开新数据库保留旧目标，不再自动关闭；批量任务应主动释放已完成的目标。
- `open_database` 支持新参数 `path`，保留 `binary_path`；返回 `instance_id`。跨库代码执行明确传入该 ID。

## 新能力

`execute_python` 提供组合分析、持久上下文、临时作用域、顶层 await 和结构化输出；`reference` 从本机 helper / Domain 源码查询 API。大结果使用完整 artifact，Python 客户端自动分页读取。会话 JSONL 和 HTML 导出按需开启。

这些接口借鉴[官方 Hex-Rays MCP](https://github.com/HexRaysSA/ida-mcp)。本项目未复现官方 token 节省 benchmark，不提供性能提升比例。

## 后端选择

| 需求 | 选择 |
| --- | --- |
| 始终纯无头、IDA 9.2 | `--backend native` |
| 始终纯无头、IDA 9.4+ | `--backend native` |
| 9.4+ GUI 或跨客户端共享 | 安装 Nexus extra，使用 `--backend nexus` |

Nexus 没有匹配实例时也可无头运行，但不会强制避开已有 GUI。`close_database(save=False)` 和 `force_reanalyze` 仅 native 支持。Nexus 的租约、事件与崩溃恢复来自官方库。

## 更新客户端

配置改为当前安装环境的绝对 Python 路径，执行 `-u -m ida_mcp_stdio`；避免同名全局安装指向其他仓库。不要把分析样本固定在全局启动参数中，按会话调用 `open_database`。

旧会话需重新加载 MCP；Claude Desktop 需重启。配置格式见[客户端配置](MCP-CLIENT-SETUP.md)，生命周期差异见[数据库管理](DATABASE-MANAGEMENT.md)。
