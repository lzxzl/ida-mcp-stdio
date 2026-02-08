# TRACE Logging Guide

## 概述

TRACE 是比 DEBUG 更详细的日志级别，用于记录完整的 JSON-RPC 请求和响应内容。这对于以下场景非常有用：

- 🔍 调试通信问题
- 📊 理解协议细节
- 🔬 监控数据流
- ⚡ 性能分析
- 🐛 问题诊断

## 日志级别对比

| 级别 | 用途 | 输出内容 |
|------|------|---------|
| **TRACE** | 详细调试 | 完整的 request/response JSON |
| **DEBUG** | 开发调试 | 方法名、参数摘要 |
| **INFO** | 常规信息 | 操作状态、耗时 |
| **WARNING** | 警告信息 | 潜在问题 |
| **ERROR** | 错误信息 | 错误详情 |

## 启用 TRACE 日志

### 方式 1: 服务端 TRACE 日志

启动服务端时指定 `--log-level TRACE`：

```bash
python -m ida_mcp_stdio binary.so --log-level TRACE
```

**效果：**
- 自动创建 `logs/` 目录
- 生成日志文件：`logs/ida-mcp-YYYYMMDD-HHMMSS.log`
- 同时输出到 stderr（INFO 级别）和文件（TRACE 级别）

**日志文件内容示例：**
```
2026-02-08 17:36:42 [TRACE] ida-mcp-stdio: Request #1 full content: {
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {
      "name": "ida-mcp-python-client",
      "version": "0.1.0"
    }
  },
  "id": 1
}

2026-02-08 17:36:42 [TRACE] ida-mcp-stdio: Response #1 full content: {
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {}
    },
    "serverInfo": {
      "name": "ida-mcp-stdio",
      "version": "0.1.0"
    }
  }
}
```

### 方式 2: 客户端 TRACE 日志

#### 选项 A: 使用 basic_usage.py（推荐）

最简单的方式，直接在命令行启用 TRACE：

```bash
# 使用 --trace 快捷参数
python examples/basic_usage.py binary.so --trace

# 或使用 --log-level TRACE
python examples/basic_usage.py binary.so --log-level TRACE

# 同时显示服务端日志
python examples/basic_usage.py binary.so --trace --verbose

# 只启用 DEBUG 级别
python examples/basic_usage.py binary.so --log-level DEBUG
```

**效果：**
- 客户端日志：`logs/ida-mcp-client-YYYYMMDD-HHMMSS.log`
- 记录客户端发送的请求和接收的响应
- 无需修改代码

**可用参数：**
```bash
python examples/basic_usage.py --help

options:
  --trace               Enable TRACE level logging
  --log-level {TRACE,DEBUG,INFO,WARNING,ERROR}
                        Set log level (default: INFO)
  --log-file            Enable file logging even if not TRACE level
  -v, --verbose         Show server logs (verbose mode)
```

#### 选项 B: 使用 trace_logging_example.py

专门的 TRACE 日志示例：

```bash
python examples/trace_logging_example.py binary.so
```

**效果：**
- 客户端日志：`logs/ida-mcp-client-YYYYMMDD-HHMMSS.log`
- 记录客户端发送的请求和接收的响应
- 包含更详细的说明

**日志文件内容示例：**
```
2026-02-08 17:36:42 [TRACE] ida-mcp-stdio.client: Sending request: {
  "jsonrpc": "2.0",
  "method": "tools/list",
  "params": {},
  "id": 2
}

2026-02-08 17:36:42 [TRACE] ida-mcp-stdio.client: Received response: {
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [...]
  }
}
```

### 方式 3: 同时启用服务端和客户端 TRACE

使用便捷脚本：

```bash
./examples/run_with_trace.sh binary.so
```

**效果：**
- 服务端日志：`logs/ida-mcp-YYYYMMDD-HHMMSS.log`
- 客户端日志：`logs/ida-mcp-client-YYYYMMDD-HHMMSS.log`
- 可以对比两端的通信内容

### 方式 4: 自定义日志文件路径

```bash
python -m ida_mcp_stdio binary.so --log-level TRACE --log-file my-debug.log
```

## 在代码中使用 TRACE 日志

### 服务端代码

```python
import logging
from datetime import datetime
from pathlib import Path

# 定义 TRACE 级别
TRACE = 5
logging.addLevelName(TRACE, "TRACE")

def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)

logging.Logger.trace = trace

# 配置日志
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
log_file = log_dir / f"my-app-{timestamp}.log"

logging.basicConfig(
    level=TRACE,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# 使用 TRACE 日志
logger.trace("Detailed debug information: %s", some_data)
```

### 客户端代码

```python
import logging
from ida_mcp_stdio import IDAMCPClient

# 启用 TRACE 日志（同上）
# ...

# 客户端会自动记录 TRACE 日志
with IDAMCPClient("binary.so") as client:
    # 所有请求/响应都会被记录到 TRACE 级别
    client.initialize()
    client.list_funcs()
```

## 日志文件结构

### 目录结构

```
project/
├── logs/
│   ├── ida-mcp-20260208-173549.log          # 服务端日志
│   ├── ida-mcp-client-20260208-173642.log   # 客户端日志
│   └── ...
├── examples/
└── src/
```

### 日志文件命名规则

- **服务端**: `ida-mcp-YYYYMMDD-HHMMSS.log`
- **客户端**: `ida-mcp-client-YYYYMMDD-HHMMSS.log`
- **自定义**: 使用 `--log-file` 指定的路径

## 日志内容分析

### 请求日志格式

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "decompile",
    "arguments": {
      "addr": "0x401000"
    }
  },
  "id": 3
}
```

**字段说明：**
- `jsonrpc`: 协议版本（固定为 "2.0"）
- `method`: 调用的方法名
- `params`: 方法参数
- `id`: 请求 ID（用于匹配响应）

### 响应日志格式

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"addr\":\"0x401000\",\"code\":\"...\"}"
      }
    ],
    "isError": false
  }
}
```

**字段说明：**
- `id`: 对应的请求 ID
- `result`: 成功响应的结果
- `error`: 错误响应（与 result 互斥）

### 错误响应格式

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "error": {
    "code": -32602,
    "message": "Invalid parameters"
  }
}
```

## 使用场景

### 场景 1: 调试通信问题

**问题**: 客户端收到意外的响应

**解决步骤：**
1. 启用 TRACE 日志
2. 重现问题
3. 查看日志文件中的请求和响应
4. 对比预期和实际的 JSON 内容

```bash
python -m ida_mcp_stdio binary.so --log-level TRACE
# 在另一个终端运行客户端
python examples/basic_usage.py binary.so
# 查看日志
cat logs/ida-mcp-*.log | grep -A 20 "Request #"
```

### 场景 2: 性能分析

**目标**: 找出哪些请求耗时最长

**步骤：**
1. 启用 TRACE 日志
2. 运行分析任务
3. 分析日志中的时间戳和耗时信息

```bash
# 提取所有工具调用的耗时
grep "Tool .* completed in" logs/ida-mcp-*.log
```

### 场景 3: 协议学习

**目标**: 理解 MCP 协议的工作方式

**步骤：**
1. 运行 trace_logging_example.py
2. 查看生成的日志文件
3. 学习请求/响应的格式和流程

```bash
python examples/trace_logging_example.py binary.so
less logs/ida-mcp-client-*.log
```

### 场景 4: 问题报告

**目标**: 向开发者报告 bug

**步骤：**
1. 启用 TRACE 日志
2. 重现问题
3. 附上日志文件

```bash
python -m ida_mcp_stdio binary.so --log-level TRACE --log-file bug-report.log
# 重现问题后，将 bug-report.log 附在 issue 中
```

## 日志分析工具

### 查看特定请求

```bash
# 查看所有 initialize 请求
grep -A 10 '"method": "initialize"' logs/ida-mcp-*.log

# 查看所有 tools/call 请求
grep -A 5 '"method": "tools/call"' logs/ida-mcp-*.log
```

### 统计请求类型

```bash
# 统计各类请求的数量
grep '"method":' logs/ida-mcp-*.log | sort | uniq -c
```

### 查找错误

```bash
# 查找所有错误响应
grep -B 5 -A 10 '"error":' logs/ida-mcp-*.log

# 查找特定错误码
grep -A 5 '"code": -32602' logs/ida-mcp-*.log
```

### 提取工具调用

```bash
# 提取所有工具调用及其参数
grep -A 3 'Calling tool:' logs/ida-mcp-*.log
```

## 性能考虑

### TRACE 日志的开销

- **CPU**: 轻微增加（JSON 序列化）
- **磁盘**: 日志文件可能很大（每个请求/响应 ~1-10KB）
- **内存**: 影响很小

### 建议

✅ **开发/调试时使用 TRACE**
- 详细的日志帮助快速定位问题
- 可以完整重现通信过程

❌ **生产环境避免使用 TRACE**
- 使用 INFO 或 WARNING 级别
- 减少磁盘 I/O 和日志文件大小

⚠️ **注意日志文件大小**
- 定期清理旧日志
- 考虑使用日志轮转

```bash
# 清理 7 天前的日志
find logs/ -name "*.log" -mtime +7 -delete

# 查看日志目录大小
du -sh logs/
```

## 日志轮转配置

如果需要长期运行并自动管理日志文件，可以使用 Python 的 `RotatingFileHandler`：

```python
from logging.handlers import RotatingFileHandler

# 最大 10MB，保留 5 个备份
handler = RotatingFileHandler(
    "logs/ida-mcp.log",
    maxBytes=10*1024*1024,
    backupCount=5,
    encoding="utf-8"
)
handler.setLevel(TRACE)
handler.setFormatter(logging.Formatter(log_format, date_format))
logger.addHandler(handler)
```

## 隐私和安全

⚠️ **注意事项：**

1. **敏感信息**: TRACE 日志包含完整的请求/响应，可能包含：
   - 二进制文件路径
   - 函数名和地址
   - 反编译代码
   - 内存内容

2. **建议：**
   - 不要分享包含敏感信息的日志
   - 报告问题时，先检查并脱敏日志内容
   - 使用 `--log-file` 指定安全的日志位置

3. **清理日志：**
   ```bash
   # 删除所有日志
   rm -rf logs/
   
   # 或只删除特定日志
   rm logs/ida-mcp-20260208-*.log
   ```

## 故障排除

### 问题 1: 日志文件未生成

**检查：**
```bash
# 确认 logs 目录存在
ls -la logs/

# 检查权限
ls -ld logs/
```

**解决：**
```bash
# 手动创建目录
mkdir -p logs
chmod 755 logs
```

### 问题 2: 日志文件为空

**原因：** 日志级别设置不正确

**解决：**
```bash
# 确保使用 TRACE 级别
python -m ida_mcp_stdio binary.so --log-level TRACE
```

### 问题 3: 日志文件太大

**解决：**
```bash
# 使用 tail 查看最后 N 行
tail -n 100 logs/ida-mcp-*.log

# 使用 less 分页查看
less logs/ida-mcp-*.log

# 压缩旧日志
gzip logs/ida-mcp-20260207-*.log
```

## 总结

TRACE 日志是强大的调试工具，能够：

✅ 完整记录所有通信内容
✅ 帮助理解协议细节
✅ 快速定位问题
✅ 支持性能分析

**使用建议：**
- 开发调试时启用 TRACE
- 生产环境使用 INFO 或更高级别
- 定期清理日志文件
- 注意保护敏感信息

**快速开始：**
```bash
# 最简单的方式
python examples/trace_logging_example.py binary.so

# 查看日志
ls -lh logs/
cat logs/ida-mcp-client-*.log
```
