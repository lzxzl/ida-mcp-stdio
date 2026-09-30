# ida-mcp-stdio

[English](README.en.md)

IDA Pro 的 MCP 服务，默认使用 stdio。可以无头运行，同时打开多个数据库，并用 Python 组合分析工具。可选的官方 Nexus 后端支持 GUI 共享。

## 安装

使用前需安装并授权 IDA Pro，确认 idalib 可用。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/ida-mcp-server --doctor
```

| 后端 | Python | IDA | 行为 |
| --- | --- | --- | --- |
| `native`，默认 | 3.10+ | idalib 9.0+；已验证 9.2、9.4 | 始终无头；每个数据库一个独立 worker |
| `nexus` | 3.11+ | 9.4+ | 复用官方实例与 GUI；没有匹配实例时启动无头 worker |

使用 Nexus 时安装：`.venv/bin/python -m pip install -e '.[nexus]'`。后端按 9.4+ 接口适配，已在 9.4 上完成实机验证。

## 启动

```sh
# 纯无头 stdio，macOS 示例
.venv/bin/ida-mcp-server --backend native \
  --ida-dir '/Applications/IDA Professional 9.4.app/Contents/MacOS'

# 9.2 同样使用 native，改成对应安装路径
# Nexus / GUI 共享
.venv/bin/ida-mcp-server --backend nexus \
  --ida-dir '/Applications/IDA Professional 9.4.app/Contents/MacOS'
```

启动时未指定二进制路径，就由客户端调用 `open_database` 开库。也可以在命令末尾附上二进制或 IDB 路径。MCP 客户端通过双向管道连接 stdio 服务。

`--ida-dir` 优先于 `IDADIR`。两者都未设置时，服务自动检测安装目录。复用 GUI 前需安装官方插件并配置 IDAPython 环境，见[客户端配置](docs/MCP-CLIENT-SETUP.md)。

## 工具

默认 `compact` 模式展示六个工具：

| 工具 | 用途 |
| --- | --- |
| `open_database` | 打开或复用数据库，返回 `instance_id` |
| `list_databases` | 查看数据库实例、状态和当前目标 |
| `save_database` | 保存指定数据库 |
| `close_database` | 保存并关闭 native worker，或释放 Nexus 租约 |
| `reference` | 离线查询本机 helper 和 Domain API 的签名、说明和源码 |
| `execute_python` | 在指定数据库中运行 Python，组合 IDAPython 与现有分析工具 |

`--tool-profile legacy` 展示原有工具；`full` 展示全部工具。未展示的已注册工具仍可按名称调用。Python 客户端默认使用 `legacy`。

## Python 示例

```python
from ida_mcp_stdio import IDAMCPClient

with IDAMCPClient(tool_profile="compact") as client:
    client.initialize()
    target = client.open_database("/path/to/binary")
    report = client.execute_python(
        "rows = tools.list_funcs(count=20)\n"
        "{'total': rows['total'], 'names': [f['name'] for f in rows['data']]}",
        instance_id=target["instance_id"],
    )
    print(report["result"])
    client.close_database(target["instance_id"])
```

每个数据库分别保留 Python 变量，末尾表达式作为返回值。代码支持顶层 `await`，执行结果包含 stdout、stderr、耗时和结构化异常。返回值必须能编码为 JSON。

native 默认最多保留四个数据库。执行中超时或取消会终止目标 worker，未保存的修改可能丢失。MCP 主服务和其他数据库仍然保留。大结果会保存为本地 artifact，Python 客户端自动读取所有分页。

Python 执行具有当前用户的文件、进程和 IDB 权限，不提供沙箱。

## 文档

- [使用指南](docs/使用指南.md)：代码执行、分析工具、结果读取。
- [客户端配置](docs/MCP-CLIENT-SETUP.md)：Codex、Claude、OpenCode、ZCode 与 GUI 环境。
- [数据库管理](docs/DATABASE-MANAGEMENT.md)：多库路由、保存、关闭与恢复。
- [架构](docs/CLIENT-ARCHITECTURE.md)、[日志](docs/TRACE-LOGGING.md)、[开发与测试](docs/MCP-SERVER-DEVELOPMENT-GUIDE.md)。
- [0.3 迁移](docs/OFFICIAL-MCP-MODERNIZATION.md)、[验证范围](docs/TESTING.md)、[可运行示例](examples/README.md)。

参考：[Hex-Rays 官方 MCP 介绍](https://hex-rays.com/blog/hex-rays-ida-mcp-server)、[官方实现](https://github.com/HexRaysSA/ida-mcp)。
