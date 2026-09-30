# MCP 客户端配置

[English](MCP-CLIENT-SETUP.en.md)

先按 [README](../README.md) 安装。将下面的 `/absolute/path/ida-mcp-stdio` 替换为实际仓库路径。使用绝对 Python 路径，避免客户端 PATH 或全局同名包指向其他环境。

## 安装与更新命令

为当前环境写入五个客户端配置：

```sh
.venv/bin/ida-mcp-server install --client all --python "$PWD/.venv/bin/python" \
  --backend nexus --ida-dir '/Applications/IDA Professional 9.4.app/Contents/MacOS' \
  --session-log auto --hooks
```

加 `--dry-run` 先查看计划，不修改文件。可用 `--client codex zcode` 选择客户端。安装命令保留其他配置，并同步更新已有同名 Claude 项目覆盖项。写入前备份原文件到 `~/.local/state/ida-mcp-stdio/backups/`。JSONC 注释、尾逗号或有歧义的配置会被拒绝，此类文件可按下方示例手工修改。

从 GitHub main 创建独立安装环境：

```sh
.venv/bin/ida-mcp-server install --venv --backend nexus --client all
# 升级当前 venv，并刷新配置
.venv/bin/ida-mcp-server update --client all
```

`--venv` 默认使用 `~/.local/share/ida-mcp-stdio/venv`，也可指定路径；`--source` 指定包或仓库来源。更新必须在 venv 中进行，先升级再写配置。它保留已有启动参数、传输方式、启用状态、超时和其他设置，只覆盖明确传入的参数；Claude 项目中的同名配置也会刷新，并保留各自的参数。不带 `--venv` 的 `install` 只写配置，默认 native、compact 和自动会话日志。

`--idle-timeout 秒数` 开启 Nexus 租约空闲释放，`0` 关闭。`--hooks` 为 Claude Code 和支持 hooks 的 Codex CLI 添加转录关联。Codex 必须已启用稳定的 hooks 能力，并在 `/hooks` 中审阅信任；安装器不改功能开关。Windows 的 Codex hooks 需手工配置。已运行客户端需要重新加载 MCP 才会使用新版本。

## 选择后端

下面的配置使用 `--backend native`，始终无头运行，支持 IDA 9.2 / 9.4。需要 9.4+ GUI 或多客户端共享时，先安装 `.[nexus]`，再改为 `--backend nexus`。Nexus 找不到匹配实例时会启动无头 worker。

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

检查：`codex mcp get ida-mcp-stdio --json`。该命令用于查看配置，不会测试连接。[Codex 配置说明](https://developers.openai.com/codex/mcp/)。

## Claude Code

用 CLI 添加用户级配置：

```sh
claude mcp add --scope user --transport stdio ida-mcp-stdio -- \
  /absolute/path/ida-mcp-stdio/.venv/bin/python -u -m ida_mcp_stdio \
  --backend native --tool-profile compact --agent claude-code
```

也可合并到 `~/.claude.json` 的 `mcpServers`。已有同名配置时，更新现有条目，并检查当前项目是否另有覆盖。

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

检查：`opencode mcp list`。示例使用已验证的 OpenCode 1.15 配置格式。[OpenCode 配置说明](https://opencode.ai/docs/mcp-servers/)。

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

将 Nexus 启动器安装在 MCP 服务使用的 Python 环境中。其他环境的 `ida-nexus` 即使在 PATH 中，也不会被使用。

```sh
.venv/bin/python -m pip install -e '.[nexus]'
uvx ida-hcli ida python create-environment
uvx ida-hcli plugin install ida-mcp@https://github.com/HexRaysSA/ida-mcp
uvx ida-hcli ida python doctor
```

按 HCLI 输出配置 `IDAPYTHON_VENV_EXECUTABLE`，让 IDA GUI 使用已安装插件依赖的 Python 环境。已启动的 GUI 不会自动获得终端环境变量。修改后重启 IDA，并在启动日志中检查 Python 路径。

## 验证与排错

- 修改配置后重新加载 MCP 或开启新会话；桌面应用可能需要重启。
- 连接后应发现六个 compact 工具；调用 `reference` 可以在不开库时检查服务。
- 再调用 `open_database`，执行 `import ida_kernwin; ida_kernwin.get_kernel_version()` 确认实际 IDA 版本。
- 开库慢时，检查客户端的工具超时设置。执行默认上限为 360 秒，示例中的客户端超时为 420 秒。
- 连接失败时先运行 `.venv/bin/ida-mcp-server --doctor`，检查 Python 环境、安装目录、Nexus launcher 与客户端 stderr 日志。

`--print-config` 只打印通用 `mcpServers` JSON，不写文件。用 `install` 可直接写入各客户端的配置格式。
