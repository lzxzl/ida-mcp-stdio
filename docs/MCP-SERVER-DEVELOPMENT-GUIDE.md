# 开发指南

[English](MCP-SERVER-DEVELOPMENT-GUIDE.en.md)

## 模块

| 路径 | 职责 |
| --- | --- |
| `src/ida_mcp_stdio/server.py` | CLI、stdio JSON-RPC、请求与取消路由 |
| `backends.py`、`worker.py` | native worker 生命周期与 Nexus adapter |
| `execution.py` | Python 执行、上下文、输出与异常 |
| `reference.py` | 本机源码 API 索引 |
| `session.py` | artifact 与 JSONL 记录 |
| `dashboard.py`、`transcripts.py`、`logs.py`、`hooks.py` | 本地看板、对话解析、ZIP 导出与客户端 hook |
| `install.py`、`cli.py` | 客户端安装 / 更新和辅助命令 |
| `gui.py` | 官方 HCLI GUI 安装计划与执行 |
| `benchmark.py`、`assets/opencode-session.js` | 固定分析任务基准、OpenCode 当前会话转录插件 |
| `http.py` | 可选 MCP SDK HTTP 传输 |
| `client.py` | Python stdio 客户端与完整结果的分页读取 |
| `tools/` | 工具注册、数据库控制、分析、内存与类型 helper |
| `structured_facts.py` | 结构化事实字段与校验 |
| `nexus_compat.py` | Darwin / Nexus 0.13.0 的 statfs ABI 修正 |

## 开发环境

下面涉及测试目录的命令只适用于保留了本地测试的工作区。克隆仓库后不会包含测试目录。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev,nexus,http]'
.venv/bin/python -m pytest tests -q
.venv/bin/python -m black --check src examples tests
.venv/bin/python -m ruff check src examples tests
.venv/bin/python -m pip wheel . --no-deps --wheel-dir dist
```

纯 native 开发可只安装 `.[dev]`。Nexus 需要 Python 3.11+，HTTP 测试需要 HTTP extra。

## 添加工具

在 `tools/` 中使用 `@register_tool`。参数使用类型注解；`Annotated` 提供参数说明。完整 docstring 进入工具说明，第一行写简洁摘要。新增模块需在 `server._import_tools()` 中导入。

```python
from typing import Annotated
from . import register_tool

@register_tool
def count_functions(limit: Annotated[int, "Result limit"] = 20) -> dict:
    import idautils
    addresses = list(idautils.Functions())
    return {"total": len(addresses), "sample": [hex(ea) for ea in addresses[:limit]]}
```

输入和结果应使用 JSON 兼容类型。分析工具在 IDA owner 中执行，数据库控制工具在父服务路由。仅在需要进入默认六工具入口时修改 profile，通常通过 `tools.<名称>()` 组合调用新增 helper。

将 IDA 导入放在实际执行的函数内，让服务初始化和 reference 查询无需加载 IDA。新增工具要覆盖参数校验和错误处理测试，并用隔离的临时样本验证 IDA 行为。修改结构化事实时，同步更新 schema 校验和客户端 wrapper。

## 协议与故障边界

stdout 只承载协议。日志写 stderr。保持请求 ID 匹配、通知无响应、严格 JSON 编码以及取消状态隔离。不要自动重试数据库修改操作。

原生 worker 持有 IDA 主线程，父进程中不能调用 IDAPython。Nexus 通过公共 `DatabaseManager` API 调度；针对已知依赖缺陷的兼容修正需要精确限定平台和版本。

## 测试与提交

本地测试位于 `tests/`，夹具位于 `tests/fixtures/`。两者均由 Git 忽略，不随仓库发布。真实 IDA 用例默认跳过，启用命令和验证范围见 [TESTING](TESTING.md)。

提交说明应写明行为变化、验证命令，以及使用的 IDA 和 Python 版本。提交源码和文档；测试、分析数据库、日志、临时样本和本机客户端配置留在本地。
