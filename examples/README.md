# IDA MCP Client Examples

本目录包含三种不同的客户端使用方式示例。

## 1. 自动启动服务端（推荐）

**文件**: `basic_usage.py`

**特点**:
- 客户端自动启动和管理服务端进程
- 最简单的使用方式
- 适合大多数场景

**使用方法**:
```bash
python examples/basic_usage.py so/libbluetooth.so
```

**工作原理**:
```
IDAMCPClient 创建
    ↓
自动启动子进程: python -m ida_mcp_stdio binary.so
    ↓
通过 stdin/stdout 通信
    ↓
客户端关闭时自动终止服务端
```

## 2. 连接到独立运行的服务端

**文件**: `connect_to_running_server.py`

**特点**:
- 客户端主动启动服务端进程，但有更多控制权
- 可以查看服务端的 stderr 输出
- 适合调试和开发场景

**使用方法**:
```bash
python examples/connect_to_running_server.py --binary so/libbluetooth.so
```

**工作原理**:
```
PipeBasedMCPClient.connect_to_command()
    ↓
启动服务端进程并捕获 stdin/stdout/stderr
    ↓
通过 pipes 通信
    ↓
可以独立查看服务端日志
```

## 3. 通过管道连接（高级用法）

**文件**: `separate_server_client.py`

**特点**:
- 服务端和客户端完全独立运行
- 通过 shell 管道或文件描述符连接
- 适合集成到其他工具或 IDE

**使用方法**:

### 方式 A: Shell 管道
```bash
python -m ida_mcp_stdio so/libbluetooth.so 2>/dev/null | \
    python examples/separate_server_client.py
```

### 方式 B: 命名管道（FIFO）
```bash
# 创建命名管道
mkfifo /tmp/ida_mcp_in /tmp/ida_mcp_out

# 终端 1: 启动服务端
python -m ida_mcp_stdio so/libbluetooth.so \
    < /tmp/ida_mcp_in > /tmp/ida_mcp_out 2>&1

# 终端 2: 运行客户端（需要修改代码读写 FIFO）
# 这需要自定义实现
```

**工作原理**:
```
服务端进程（独立运行）
    ↓ stdin/stdout
Shell 管道 或 命名管道
    ↓ stdin/stdout
客户端进程（独立运行）
```

## 使用场景对比

| 场景 | 推荐方式 | 文件 |
|------|---------|------|
| 日常分析任务 | 自动启动 | `basic_usage.py` |
| 调试服务端代码 | 独立进程 | `connect_to_running_server.py` |
| IDE 集成 | 管道连接 | `separate_server_client.py` |
| 批量处理 | 自动启动 | `basic_usage.py` |
| 远程分析 | 需要额外实现 TCP/WebSocket | - |

## 代码对比

### 自动启动方式
```python
from ida_mcp_stdio import IDAMCPClient

with IDAMCPClient("binary.so", verbose=True) as client:
    client.initialize()
    funcs = client.list_funcs()
    # 自动清理
```

### 独立进程方式
```python
from examples.connect_to_running_server import PipeBasedMCPClient

command = ["python", "-m", "ida_mcp_stdio", "binary.so"]
with PipeBasedMCPClient.connect_to_command(command) as client:
    client.initialize()
    funcs = client.call_tool("list_funcs", {"count": 10})
    # 自动清理
```

### 管道方式
```python
from examples.separate_server_client import ExternalMCPClient

# 假设已通过管道连接
client = ExternalMCPClient()
client.initialize()
funcs = client.call_tool("list_funcs", {"count": 10})
```

## 注意事项

1. **日志输出**: 
   - 服务端日志输出到 stderr
   - JSON-RPC 通信使用 stdin/stdout
   - 客户端日志应输出到 stderr 避免干扰通信

2. **进程管理**:
   - 自动启动方式：客户端负责清理
   - 独立进程方式：需要手动管理或使用 context manager
   - 管道方式：需要外部管理服务端生命周期

3. **错误处理**:
   - 检查 `is_running` 状态
   - 捕获 `ConnectionError`, `TimeoutError`
   - 查看服务端 stderr 获取详细错误信息

4. **性能考虑**:
   - 启动服务端需要加载 IDA 数据库（可能较慢）
   - 复用同一个服务端进程可以提高效率
   - 考虑使用连接池管理多个服务端实例

## 扩展阅读

- [MCP 协议规范](https://modelcontextprotocol.io/)
- [IDA Python API 文档](https://hex-rays.com/products/ida/support/idapython_docs/)
- [JSON-RPC 2.0 规范](https://www.jsonrpc.org/specification)
