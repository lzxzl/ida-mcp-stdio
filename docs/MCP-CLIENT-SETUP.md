# MCP 客户端配置

先按 [README](../README.md) 安装。以下 `/absolute/path/ida-mcp-stdio` 替换为实际仓库路径。使用绝对 Python 路径，避免客户端 PATH 或全局同名包指向其他环境。

## 选择后端

所有示例使用 `--backend native`，始终纯无头，支持 IDA 9.2 / 9.4。需要 9.4+ GUI 或多客户端共享时，先安装 `.[nexus]`，再改为 `--backend nexus`；Nexus 没有匹配实例时启动无头 worker。

需要固定 IDA 版本时，在 args / command 数组末尾增加两个元素：`"--ida-dir"` 和安装路径。macOS 例如 `/Applications/IDA Professional 9.4.app/Contents/MacOS`。也可设置 `IDADIR`。

## Codex

编辑 `~/.codex/config.toml`：

```toml
[mcp_servers.ida-mcp-stdio]
command = "/absolute/path/ida-mcp-stdio/.venv/bin/python"
args = ["-u", "-m", "ida_mcp_stdio", "--backend", "native", "--tool-profile", "compact", "--agent", "codex"]
enabled = true
startup_timeout_sec = 30
tool_timeout_sec = 420
```

检查：`codex mcp get ida-mcp-stdio --json`。该命令查看配置，不代表完成连接测试。[Codex 配置说明](https://developers.openai.com/codex/mcp/)。

## Claude Code

用 CLI 添加用户级配置：

```sh
claude mcp add --scope user --transport stdio ida-mcp-stdio -- \
  /absolute/path/ida-mcp-stdio/.venv/bin/python -u -m ida_mcp_stdio \
  --backend native --tool-profile compact --agent claude-code
```

也可合并到 `~/.claude.json` 的 `mcpServers`。已有同名配置时更新现有条目；检查当前项目是否另有覆盖。

```json
{
  "mcpServers": {
    "ida-mcp-stdio": {
      "type": "stdio",
      "command": "/absolute/path/ida-mcp-stdio/.venv/bin/python",
      "args": ["-u", "-m", "ida_mcp_stdio", "--backend", "native", "--tool-profile", "compact", "--agent", "claude-code"],
      "timeout": 420000
    }
  }
}
```

检查：`claude mcp get ida-mcp-stdio`。[Claude Code 配置说明](https://code.claude.com/docs/en/mcp)。

## Claude Desktop

macOS 配置位于 `~/Library/Application Support/Claude/claude_desktop_config.json`，合并以下条目到已有 `mcpServers`：

```json
{
  "mcpServers": {
    "ida-mcp-stdio": {
      "command": "/absolute/path/ida-mcp-stdio/.venv/bin/python",
      "args": ["-u", "-m", "ida_mcp_stdio", "--backend", "native", "--tool-profile", "compact", "--agent", "claude-desktop"]
    }
  }
}
```

保存后重启 Claude Desktop。其他平台通过应用设置打开对应配置文件。

## OpenCode

合并到 `~/.config/opencode/opencode.json` 的 `mcp`：

```json
{
  "mcp": {
    "ida-mcp-stdio": {
      "type": "local",
      "command": ["/absolute/path/ida-mcp-stdio/.venv/bin/python", "-u", "-m", "ida_mcp_stdio", "--backend", "native", "--tool-profile", "compact", "--agent", "opencode"],
      "enabled": true,
      "timeout": 420000
    }
  }
}
```

检查：`opencode mcp list`。本示例采用已验证的 OpenCode 1.15 配置格式。[OpenCode 配置说明](https://opencode.ai/docs/mcp-servers/)。

## ZCode

合并到 `~/.zcode/cli/config.json` 的 `mcp.servers`：

```json
{
  "mcp": {
    "servers": {
      "ida-mcp-stdio": {
        "type": "stdio",
        "command": "/absolute/path/ida-mcp-stdio/.venv/bin/python",
        "args": ["-u", "-m", "ida_mcp_stdio", "--backend", "native", "--tool-profile", "compact", "--agent", "zcode"],
        "timeoutMs": 420000
      }
    }
  }
}
```

ZCode 默认启用服务器。重新加载 MCP 后，在应用的 MCP 管理界面查看连接状态。[ZCode 配置说明](https://zcode.z.ai/en/docs/mcp-services)、[CLI 字段说明](https://github.com/zai-org/ZCode/blob/main/apps/zcode-cli/README.md#mcp-configuration)。

## Nexus / GUI 环境

Nexus 启动器需安装在运行 MCP 服务的同一 Python 环境；仅把其他环境的 `ida-nexus` 加入 PATH 无效。

```sh
.venv/bin/python -m pip install -e '.[nexus]'
uvx ida-hcli ida python create-environment
uvx ida-hcli plugin install ida-mcp@https://github.com/HexRaysSA/ida-mcp
uvx ida-hcli ida python doctor
```

按 HCLI 输出配置 `IDAPYTHON_VENV_EXECUTABLE`，让 IDA GUI 使用已安装插件依赖的 Python 环境。终端环境变量不会自动传给已启动的 GUI；修改后重启 IDA，并检查启动日志中的 Python 路径。

## 验证与排错

- 修改配置后重新加载 MCP 或开启新会话；桌面应用可能需要重启。
- 连接后应发现六个 compact 工具；调用 `reference` 可以在不开库时检查服务。
- 再调用 `open_database`，执行 `import ida_kernwin; ida_kernwin.get_kernel_version()` 确认实际 IDA 版本。
- 开库慢时检查客户端工具超时；执行默认 360 秒，示例配置给客户端 420 秒。
- 连接失败时先运行 `.venv/bin/ida-mcp-server --doctor`，检查 Python 环境、安装目录、Nexus launcher 与客户端 stderr 日志。

`--print-config` 只生成通用 `mcpServers` JSON，不会自动修改客户端配置，也不能直接替代 Codex TOML、OpenCode 或 ZCode 的专用格式。
