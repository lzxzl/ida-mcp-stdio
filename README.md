# IDA Pro MCP stdio

简化的 IDA Pro MCP 服务器，使用 stdio 传输和 idalib（无头模式）。

## 概述

本项目提供一个精简的 MCP（Model Context Protocol）服务器，用于 IDA Pro 二进制分析。使用 stdio 通信和 idalib 无头分析，无需 HTTP 传输和线程同步机制。

**核心特点：**
- 纯 stdio 传输，兼容所有 MCP 客户端
- 基于 idalib 的无头分析（不需要 IDA Pro GUI）
- 15+ 分析工具，覆盖反编译、反汇编、交叉引用、内存读取、类型分析
- Python 客户端库，支持编程调用
- 结构化日志和详细错误诊断


## 架构对比

### 原始 HTTP 架构 vs 新 stdio + idalib 架构

本项目是 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 的简化版本，采用了不同的架构设计。

#### 原始 HTTP 架构（用于 IDA Pro GUI）

```
┌─────────────────┐
│  MCP 客户端     │ (Claude/Cursor/Kiro 等)
└────────┬────────┘
         │ stdio/JSON-RPC
         ▼
┌─────────────────┐
│  MCP 服务器     │ (server.py - 外部 Python 进程)
│  代理层         │ 负责 stdio ↔ HTTP 转换
└────────┬────────┘
         │ HTTP POST to localhost:13337/mcp
         ▼
┌─────────────────────────────┐
│  IDA 插件 (ida_mcp/)        │ (运行在 IDA Pro 进程内)
│  - HTTP 服务器              │
│  - 工具注册和执行           │
│  - IDA SDK 调用             │
└────────┬────────────────────┘
         │ execute_sync() 到主线程
         ▼
┌─────────────────┐
│  IDA 主线程     │
│  - IDA SDK      │
│  - 数据库操作   │
└─────────────────┘
```

**特点**：
- **3 个进程**：MCP 客户端 → 外部服务器 → IDA Pro
- **通信方式**：stdio → HTTP → IDA SDK
- **线程同步**：必需（`@idasync` 装饰器）
- **UI 要求**：需要 IDA Pro GUI
- **使用场景**：与 AI 助手交互式逆向工程
- **复杂度**：较高（HTTP 层、线程同步）
- **性能**：有 HTTP 开销

#### 新 stdio + idalib 架构（本项目 - 无头模式）

```
┌─────────────────────────────────┐
│  MCP 客户端                     │
│  - Claude Desktop/Cursor/Kiro   │
│  - Python 客户端库 (IDAMCPClient)│
└───────────┬─────────────────────┘
            │ stdio (JSON-RPC)
            ▼
┌─────────────────────────────────┐
│  MCP 服务器 (ida-mcp-server)    │
│  - 接收 stdio 请求              │
│  - 直接调用 idalib              │
│  - 工具注册和执行               │
└───────────┬─────────────────────┘
            │ 直接函数调用
            ▼
┌─────────────────────────────────┐
│  idalib (IDA 无头模式)          │
│  - 反编译                       │
│  - 反汇编                       │
│  - 交叉引用                     │
│  - 所有 IDA 功能                │
└─────────────────────────────────┘
```

**特点**：
- **单进程架构**：MCP 服务器内嵌 idalib
- **通信方式**：stdio → 直接 idalib 调用
- **线程同步**：不需要（单线程）
- **UI 要求**：无头模式（无 GUI）
- **客户端支持**：标准 MCP 客户端 + Python 库
- **使用场景**：AI 辅助分析、自动化、批处理
- **复杂度**：较低（无 HTTP、无线程同步）
- **性能**：更快（直接函数调用）

#### 详细对比表

| 特性 | HTTP 架构（原始） | stdio + idalib 架构（本项目） |
|------|------------------|------------------------------|
| **UI** | IDA Pro GUI 必需 | 无头模式 |
| **架构** | 3 层（客户端、代理、IDA） | 2 层（客户端、服务器+idalib） |
| **通信** | stdio → HTTP → IDA SDK | stdio → idalib |
| **线程同步** | 必需（`execute_sync`） | 不需要 |
| **复杂度** | 高 | 低 |
| **性能** | HTTP 开销 | 直接调用，更快 |
| **安装** | 需要安装插件到 IDA | 仅需 Python 包 |
| **MCP 客户端** | ✅ 支持（Claude等） | ✅ 支持（CClaude等） |
| **Python 客户端** | ❌ 不提供 | ✅ 提供（IDAMCPClient） |
| **使用场景** | 交互式 AI 辅助逆向 | AI 辅助 + 自动化 + 批处理 |
| **Web 配置界面** | 有（`/config.html`） | 无 |
| **安全防护** | 需要 CORS、CSRF 防护 | 本地通信，更简单 |
| **调试** | 跨进程调试较复杂 | 单进程，易于调试 |
| **部署** | 需要 IDA Pro GUI 环境 | 仅需 idalib |

#### 为什么需要两种架构？

**原始架构使用 HTTP 的原因**：

1. **进程隔离的必然选择**
   - 外部 MCP 服务器和 IDA 插件运行在**两个不同的进程**中
   - 外部服务器：普通 Python 进程，处理 stdio 通信
   - IDA 插件：运行在 IDA Pro 进程内，可以调用 IDA SDK
   - 需要进程间通信（IPC）机制，HTTP 是最简单、最通用的方式

2. **IDA Pro 的架构限制**
   - IDA SDK 必须在 IDA Pro 进程内才能调用
   - IDA Pro 是一个 GUI 应用程序
   - 插件必须作为 DLL/SO 加载到 IDA 进程中
   - 外部进程无法直接访问 IDA 的内存和数据结构

3. **Web 配置界面**
   - 提供 `/config.html` Web 配置界面
   - 工具启用/禁用管理
   - CORS 策略配置
   - 输出下载功能

**本项目不需要 HTTP 的原因**：

**关键区别**：使用 **idalib**（无头模式）

- **idalib 是一个 Python 包**，可以在任何 Python 进程中导入
- 不需要 IDA Pro GUI
- 不需要插件机制
- 不需要进程间通信
- 可以直接在同一进程内调用 IDA 功能

#### 使用场景选择

**使用 HTTP 架构（原始项目）当你需要**：
- ✅ 在 IDA Pro GUI 中交互式工作
- ✅ 希望在 IDA UI 中实时看到变化
- ✅ 需要 Web 配置界面
- ✅ 使用现有的 IDA Pro 安装和插件

**使用 stdio + idalib 架构（本项目）当你需要**：
- ✅ 使用 AI 助手（Claude、Cursor、Kiro 等）进行无头分析
- ✅ 构建自动化分析工具
- ✅ 批量处理多个二进制文件
- ✅ 不需要 GUI 交互
- ✅ 更简单、更快的集成
- ✅ 使用 Python 客户端库编程
- ✅ 在 CI/CD 管道中运行分析
- ✅ 更低的资源占用（无 GUI）

#### 本项目的优势

1. **更简单**
   - 去掉 HTTP 层和线程同步
   - 代码更少，更易理解
   - 无需配置端口和安全策略

2. **更快**
   - 直接函数调用，无网络开销
   - 无 JSON 序列化/反序列化开销
   - 无 HTTP 请求/响应开销

3. **更灵活**
   - 完全控制客户端和服务器
   - 可以自定义通信协议
   - 易于集成到现有工具链

4. **易于调试**
   - 单进程，日志清晰
   - 可以直接使用 Python 调试器
   - 无跨进程调试的复杂性

5. **独立部署**
   - 可以单独拷贝使用
   - 不依赖 IDA Pro GUI
   - 适合容器化部署


## 前置要求

- Python >= 3.10
- IDA Pro >= 9.0（需要 idalib 支持）
- `idapro` Python 包（由 IDA Pro 安装目录提供，非 PyPI 包）

> **关于 IDADIR**：服务器启动时会自动检测 IDA Pro 安装路径并设置 `IDADIR` 环境变量。支持 macOS（`/Applications/IDA*.app`）、Linux（`/opt/idapro`）、Windows（`Program Files/IDA*`）常见安装位置。如果自动检测失败或安装在非标准位置，需手动设置：`export IDADIR=/path/to/ida`

## 安装

```bash
pip install .
```

开发模式安装：

```bash
pip install -e ".[dev]"
```

## 快速开始

### 作为 MCP 服务器

```bash
ida-mcp-server /path/to/binary.exe
```

启用详细日志：

```bash
ida-mcp-server /path/to/binary.exe --verbose
```

指定日志级别：

```bash
ida-mcp-server /path/to/binary.exe --log-level DEBUG
```

### 配置 MCP 客户端

在 Claude Desktop 的 `claude_desktop_config.json` 中添加：

```json
{
  "mcpServers": {
    "ida-pro": {
      "command": "ida-mcp-server",
      "args": ["/path/to/binary.exe"]
    }
  }
}
```

更多客户端配置见 [docs/MCP-CLIENT-SETUP.md](docs/MCP-CLIENT-SETUP.md)。

### Python 客户端

项目提供三种客户端使用方式，详见 [examples/README.md](examples/README.md) 和 [架构对比文档](docs/CLIENT-ARCHITECTURE.md)。

#### 方式 1: 自动启动服务端（推荐）

```python
from ida_mcp_stdio import IDAMCPClient

with IDAMCPClient("binary.exe", verbose=True) as client:
    client.initialize()

    # 列出函数
    funcs = client.list_funcs(count=10)
    for f in funcs["data"]:
        print(f"{f['addr']} {f['name']}")

    # 反编译
    result = client.decompile("main")
    print(result["code"])

    # 反汇编
    asm = client.disasm("main", max_instructions=20)
    for line in asm["lines"]:
        print(f"  {line['addr']}: {line['text']}")
```

运行示例：
```bash
python examples/basic_usage.py /path/to/binary.exe
```

#### 方式 2: 连接到独立服务端（调试用）

```python
from examples.connect_to_running_server import PipeBasedMCPClient

command = ["python", "-m", "ida_mcp_stdio", "binary.exe"]
with PipeBasedMCPClient.connect_to_command(command) as client:
    client.initialize()
    funcs = client.call_tool("list_funcs", {"count": 10})
```

#### 方式 3: 管道连接（高级）

```bash
python -m ida_mcp_stdio binary.exe 2>/dev/null | \
    python examples/separate_server_client.py
```

## 可用工具

| 类别 | 工具 | 说明 |
|------|------|------|
| 分析 | `decompile` | 反编译函数为伪代码 |
| 分析 | `disasm` | 反汇编指定地址指令 |
| 分析 | `list_funcs` | 列出函数（支持过滤/分页） |
| 分析 | `xrefs_to` | 获取交叉引用 |
| 分析 | `callees` | 获取被调用函数 |
| 分析 | `find_bytes` | 搜索字节模式（支持通配符） |
| 分析 | `imports` | 列出导入符号 |
| 分析 | `list_globals` | 列出全局变量 |
| 内存 | `get_bytes` | 读取原始字节 |
| 内存 | `get_int` | 读取整数值 |
| 内存 | `get_string` | 读取字符串 |
| 内存 | `get_segment_bytes` | 读取段数据 |
| 类型 | `search_structs` | 搜索结构体 |
| 类型 | `read_struct` | 读取结构体字段 |
| 类型 | `export_funcs` | 导出函数信息 |

## 错误处理

客户端提供三种错误类型：

```python
from ida_mcp_stdio import MCPError, MCPToolError, MCPConnectionError

try:
    result = client.decompile("invalid")
except MCPToolError as e:
    print(f"工具错误: {e.tool_name} - {e.message}")
except MCPError as e:
    print(f"协议错误 [{e.code}]: {e.message}")
except MCPConnectionError as e:
    print(f"连接错误: {e}")
except TimeoutError:
    print("请求超时")
```

## 项目结构

```
src/ida_mcp_stdio/
├── __init__.py          # 包入口和导出
├── __main__.py          # 命令行入口
├── server.py            # MCP 服务器（JSON-RPC over stdio）
├── client.py            # Python 客户端
├── utils.py             # 工具函数
└── tools/
    ├── __init__.py      # 工具注册系统
    ├── analysis.py      # 分析工具（8 个）
    ├── memory.py        # 内存工具（4 个）
    └── types.py         # 类型工具（3 个）
```

## 文档

### 入门指南
- [快速开始](docs/QUICKSTART.md) - 5 分钟快速上手
- [使用指南](docs/使用指南.md) - 完整的中文使用文档

### 配置和问题
- [MCP 客户端配置](docs/MCP-CLIENT-SETUP.md) - 各种 MCP 客户端配置方法

### 高级功能
- [TRACE 日志](docs/TRACE-LOGGING.md) - 详细的请求/响应日志记录
- [客户端架构](docs/CLIENT-ARCHITECTURE.md) - 深入理解客户端架构设计

### 示例和参考
- [示例代码](examples/README.md) - 三种客户端使用方式对比

### 示例文件
- `examples/basic_usage.py` - 自动启动服务端（推荐）
- `examples/connect_to_running_server.py` - 连接到独立服务端（调试用）
- `examples/separate_server_client.py` - 管道连接（高级用法）
- `examples/trace_logging_example.py` - TRACE 日志示例
- `examples/test_all_modes.sh` - 测试所有模式的脚本
- `examples/run_with_trace.sh` - 启用 TRACE 日志运行

## 测试

```bash
# 运行所有测试
python -m pytest tests/ -v

# 运行覆盖率报告
python -m pytest tests/ --cov=ida_mcp_stdio --cov-report=term-missing
```

## 许可证

MIT
