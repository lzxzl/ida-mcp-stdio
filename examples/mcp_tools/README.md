# MCP Tools Manual Tests

这个目录包含所有 15 个 MCP 工具的手动测试脚本。

## 📋 工具列表

### 分析工具 (8 个)
1. **decompile** - 反编译函数为伪代码
2. **list_funcs** - 列出二进制文件中的函数
3. **disasm** - 反汇编指令
4. **xrefs_to** - 获取交叉引用
5. **callees** - 获取被调用的函数
6. **find_bytes** - 搜索字节模式
7. **imports** - 列出导入符号
8. **list_globals** - 列出全局变量

### 内存工具 (4 个)
9. **get_bytes** - 读取原始字节
10. **get_int** - 读取整数值
11. **get_string** - 读取字符串
12. **get_segment_bytes** - 读取段数据

### 类型工具 (3 个)
13. **search_structs** - 搜索结构体类型
14. **read_struct** - 读取结构体定义和内存值
15. **export_funcs** - 导出函数信息

## 🚀 使用方法

### 测试所有工具
```bash
python examples/mcp_tools/test_all_tools.py /path/to/binary
```

### 测试特定类别

#### 分析工具
```bash
python examples/mcp_tools/test_analysis_tools.py /path/to/binary
```

#### 内存工具
```bash
python examples/mcp_tools/test_memory_tools.py /path/to/binary
```

#### 类型工具
```bash
python examples/mcp_tools/test_type_tools.py /path/to/binary
```

### 启用 TRACE 日志
```bash
python examples/mcp_tools/test_all_tools.py /path/to/binary --trace
```

### 显示服务端日志
```bash
python examples/mcp_tools/test_all_tools.py /path/to/binary --verbose
```

## �️ 诊断工具

### 1. debug_ida_state.py - IDA 状态检查

直接检查 IDA 数据库的内部状态：

```bash
python examples/mcp_tools/debug_ida_state.py binary.so
```

**输出信息**：
- 数据库地址范围（Min EA / Max EA）
- 文件类型
- 函数总数
- 段信息
- 代码地址统计

**用途**：快速诊断数据库是否正常加载

### 2. diagnose_database.py - 数据库诊断

测试多个 MCP 工具并提供诊断建议：

```bash
python examples/mcp_tools/diagnose_database.py binary.so
```

**测试内容**：
- list_funcs - 函数列表
- imports - 导入符号
- find_bytes - 字节搜索
- list_globals - 全局变量

**用途**：全面检查数据库功能

### 3. decompile_function.py - 函数反编译

按名称或地址反编译函数：

```bash
# 列出所有函数
python examples/mcp_tools/decompile_function.py binary.so --list

# 搜索函数（支持通配符）
python examples/mcp_tools/decompile_function.py binary.so --search "*bte_load*"
python examples/mcp_tools/decompile_function.py binary.so --search "main"

# 按函数名反编译
python examples/mcp_tools/decompile_function.py binary.so _Z17bte_load_did_confPKc
python examples/mcp_tools/decompile_function.py binary.so main

# 按地址反编译
python examples/mcp_tools/decompile_function.py binary.so 0x188a54

# 同时显示反汇编
python examples/mcp_tools/decompile_function.py binary.so main --disasm

# 显示更多函数
python examples/mcp_tools/decompile_function.py binary.so --list --count 100
```

**用途**：快速反编译特定函数，无需编写代码

---

## 📊 测试输出示例

### 成功的测试
```
Test 2: list_funcs
============================================================

2.1 Basic listing (first 5 functions):
Total functions: 13387
Returned: 5
More available: True
  0x188a54 __on_dlclose (size: 12)
  0x188a64 __on_dlclose_late (size: 4)
  0x188a68 __atexit_handler_wrapper (size: 12)
  0x188a74 atexit (size: 28)
  0x188a90 pthread_atfork (size: 12)
✅ list_funcs works!
```

### 警告（预期行为）
```
Test 11: get_string
============================================================
Trying to read string from function address 0x188a54:
  ⚠️  Invalid address: 0x188a54 (expected, not a string)
```

### 错误（需要检查）
```
Test 1: decompile
============================================================
❌ Error: Decompilation failed
```

## � 代码解释i

### list_funcs 代码
```python
funcs = client.list_funcs(count=10)
# 调用 list_funcs 工具，请求最多 10 个函数
# 返回格式：
# {
#   "data": [{"addr": "0x...", "name": "...", "size": ...}, ...],
#   "total": 总数,
#   "more": 是否还有更多,
#   "offset": 当前偏移,
#   "count": 返回数量
# }

for func in funcs.get("data", []):
    # 遍历返回的函数列表
    # .get("data", []) 表示如果没有 data 字段，使用空列表
    print(f"{func['addr']} {func['name']} (size: {func.get('size', '?')})")
    # func['addr']: 函数地址
    # func['name']: 函数名称
    # func.get('size', '?'): 函数大小，如果没有则显示 '?'

if funcs.get("more"):
    # 如果还有更多函数（分页）
    print(f"... and more (total: {funcs.get('total', '?')})")
```

### 分页示例
```python
# 获取所有函数（分页）
offset = 0
batch_size = 100
all_funcs = []

while True:
    funcs = client.list_funcs(offset=offset, count=batch_size)
    all_funcs.extend(funcs.get("data", []))
    
    if not funcs.get("more"):
        break
    
    offset += batch_size

print(f"Total functions collected: {len(all_funcs)}")
```

## 🎯 测试技巧

### 1. 快速测试单个工具
```python
from ida_mcp_stdio import IDAMCPClient

with IDAMCPClient("binary.so") as client:
    client.initialize()
    
    # 测试 list_funcs
    result = client.list_funcs(count=5)
    print(result)
```

### 2. 测试错误处理
```python
from ida_mcp_stdio import MCPToolError

try:
    result = client.decompile("invalid_address")
except MCPToolError as e:
    print(f"Expected error: {e.message}")
```

### 3. 性能测试
```python
import time

start = time.time()
result = client.list_funcs(count=1000)
elapsed = time.time() - start
print(f"Time: {elapsed:.3f}s")
```

## 📚 相关文档

- [使用指南](../../docs/使用指南.md) - 所有工具的详细说明
- [快速参考](../../QUICK-REFERENCE.md) - 命令速查
- [TRACE 日志](../../docs/TRACE-LOGGING.md) - 调试指南

## 🐛 报告问题

如果测试失败：

1. 启用 TRACE 日志：`--trace`
2. 查看日志文件：`logs/test-all-tools-*.log`
3. 检查服务端日志
4. 提供最小复现代码

## ✅ 预期结果

运行 `test_all_tools.py` 应该看到：

- ✅ 表示测试成功
- ⚠️  表示预期的警告（如地址不是字符串）
- ❌ 表示错误（需要检查）

大多数工具应该返回 ✅，少数可能返回 ⚠️（取决于二进制文件）。
