# 开发指南

## 模块

| 路径 | 职责 |
| --- | --- |
| `src/ida_mcp_stdio/server.py` | CLI、stdio JSON-RPC、请求与取消路由 |
| `backends.py`、`worker.py` | native worker 生命周期与 Nexus adapter |
| `execution.py` | Python 执行、上下文、输出与异常 |
| `reference.py` | 本机源码 API 索引 |
| `session.py`、`dashboard.py` | artifact、JSONL 与 HTML 导出 |
| `http.py` | 可选 MCP SDK HTTP 传输 |
| `client.py` | Python stdio 客户端与结果分页恢复 |
| `tools/` | 工具注册、数据库控制、分析、内存与类型 helper |
| `structured_facts.py` | 结构化事实字段与校验 |
| `nexus_compat.py` | Darwin / Nexus 0.13.0 的 statfs ABI 修正 |

## 开发环境

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

IDA 导入应留在需要执行的函数内，保持服务初始化和 reference 查询不依赖已加载 IDA。新增工具需有参数校验和错误路径测试；IDA 行为使用隔离临时样本验证。结构化事实变动同步修改 schema 校验与客户端 wrapper。

## 协议与故障边界

stdout 只承载协议。日志写 stderr。保持请求 ID 匹配、通知无响应、严格 JSON 编码以及取消状态隔离。不要自动重试数据库修改操作。

原生 worker 拥有 IDA 主线程；不要从父进程调用 IDAPython。Nexus 通过公共 `DatabaseManager` API 调度；针对已知依赖缺陷的兼容修正需要精确限定平台和版本。

## 测试与提交

正式测试位于 `tests/`；`tests/fixtures/` 是测试依赖，保留在仓库。真实 IDA 用例默认跳过，启用命令和验证范围见 [TESTING](TESTING.md)。

提交说明应包含行为变化、执行过的验证命令和相关 IDA / Python 版本。只提交源码、文档和正式测试；分析数据库、日志、临时样本和本机客户端配置保持在仓库外。
