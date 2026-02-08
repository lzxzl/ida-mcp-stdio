# MCP 客户端配置指南

本文档说明如何在各种 MCP 客户端中配置 IDA Pro MCP stdio 服务器。

## Claude Desktop

### 配置文件位置

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### 配置示例

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

### 带详细日志

```json
{
  "mcpServers": {
    "ida-pro": {
      "command": "ida-mcp-server",
      "args": ["/path/to/binary.exe", "--verbose"]
    }
  }
}
```

### 使用 Python 路径

如果 `ida-mcp-server` 不在 PATH 中：

```json
{
  "mcpServers": {
    "ida-pro": {
      "command": "/path/to/python",
      "args": ["-m", "ida_mcp_stdio", "/path/to/binary.exe"]
    }
  }
}
```

## Claude Code

在项目根目录的 `.mcp.json` 中添加：

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

## Cursor

### 配置文件位置

`~/.cursor/mcp.json`

### 配置示例

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

## Cline / Roo Code（VS Code 扩展）

### 配置文件位置

- **Cline**: `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- **Roo Code**: 类似路径，扩展 ID 不同

### 配置示例

```json
{
  "mcpServers": {
    "ida-pro": {
      "command": "ida-mcp-server",
      "args": ["/path/to/binary.exe"],
      "alwaysAllow": [
        "decompile", "disasm", "list_funcs",
        "xrefs_to", "callees", "find_bytes",
        "imports", "list_globals",
        "get_bytes", "get_int", "get_string", "get_segment_bytes",
        "search_structs", "read_struct", "export_funcs"
      ]
    }
  }
}
```

`alwaysAllow` 列出不需要用户确认的工具名称。所有分析工具都是只读的，可以安全设为自动批准。

## Windsurf

### 配置文件位置

`~/.windsurf/mcp.json`

### 配置示例

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

## 通用注意事项

### 二进制路径

所有配置中的 `args` 第一个参数是要分析的二进制文件路径。使用绝对路径以避免路径问题。

### IDADIR 环境变量

服务器启动时会自动检测 IDA Pro 安装路径（支持 macOS、Linux、Windows 常见安装位置）。如果 IDA 安装在非标准位置且自动检测失败，可通过 `env` 字段手动指定 `IDADIR`：

```json
{
  "mcpServers": {
    "ida-pro": {
      "command": "ida-mcp-server",
      "args": ["/path/to/binary.exe"],
      "env": {
        "IDADIR": "/path/to/ida/installation"
      }
    }
  }
}
```

> 如果已手动设置 `IDADIR` 环境变量，服务器不会覆盖它。

### 多个二进制

如需同时分析多个二进制，配置多个服务器实例：

```json
{
  "mcpServers": {
    "ida-main-exe": {
      "command": "ida-mcp-server",
      "args": ["/path/to/main.exe"]
    },
    "ida-lib-dll": {
      "command": "ida-mcp-server",
      "args": ["/path/to/lib.dll"]
    }
  }
}
```

## 常见问题

### Q: 服务器启动失败

1. 检查 `idapro` 包是否可用：

```bash
python -c "import idapro; print('OK')"
```

2. 如果报 `Cannot load IDA library file libidalib.dylib`，说明找不到 IDA 库文件。服务器会自动检测常见安装路径，但如果 IDA 安装在非标准位置，需手动设置：

```bash
export IDADIR=/path/to/ida
```

3. 如果 `idapro` 包本身不存在，确认 IDA Pro >= 9.0 已安装且 Python 版本正确。使用 `idapyswitch` 切换 Python 版本。

### Q: 工具调用无响应

大型二进制的首次加载和分析可能需要较长时间。在 args 中添加 `--verbose` 查看进度日志。

### Q: 如何更换分析的二进制

需要修改配置文件中的路径并重启 MCP 客户端。目前不支持运行时切换二进制。
