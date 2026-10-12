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

加 `--dry-run` 先查看计划，不修改文件。可用 `--client codex zcode` 选择客户端。安装命令保留其他配置；`update` 同步刷新已有同名 Claude 项目覆盖项。写入前备份原文件到 `~/.local/state/ida-mcp-stdio/backups/`。JSONC 注释、尾逗号或有歧义的配置会被拒绝，此类文件可按下方示例手工修改。

从 GitHub main 创建独立安装环境：

```sh
.venv/bin/ida-mcp-server install --venv --backend nexus --client all
# 升级当前 venv，并刷新配置
.venv/bin/ida-mcp-server update --client all
```

`--venv` 默认使用 `~/.local/share/ida-mcp-stdio/venv`，也可指定路径；`--source` 指定包或仓库来源。更新必须在 venv 中进行，先升级再写配置。它保留已有启动参数、传输方式、启用状态、超时和其他设置，只覆盖明确传入的参数；Claude 项目中的同名配置也会刷新，并保留各自的参数。不带 `--venv` 或 `--gui-plugin` 的 `install` 只写配置，默认 native、compact 和自动会话日志。

默认来源是远端 main。试用本地尚未推送的改动时，加 `--source /absolute/path/ida-mcp-stdio`，从当前工作目录安装。

`--idle-timeout 秒数` 开启 Nexus 租约空闲释放，`0` 关闭。`--hooks` 为 Claude Code、支持 hooks 的 Codex CLI、OpenCode 和 ZCode 添加当前会话转录关联。它保留其他 hooks 和已有禁用状态。Codex 必须已启用稳定的 hooks 能力，并在 `/hooks` 中审阅信任；安装器不改功能开关。Windows 的 Codex hooks 需手工配置。已运行客户端需要重新加载 MCP 才会使用新版本。

OpenCode 安装本地插件到 `~/.config/opencode/plugins/ida-mcp-stdio.js`，使用已验证的 V1 插件接口（OpenCode 1.15.13、SDK 1.14.40）。ZCode 使用 `hooks.events`；请在设置中检查是否启用 hooks。ZCode 3.14.5 的临时转录仅提供当前提示词或最终回答，保存后的记录包含相关 IDA 工具事件；缺失的用量保持不可用。Claude Desktop 没有已支持的自动转录接口，可显式关联导出文件。OpenCode / ZCode 的保存目录在安装时确定；改变 `IDA_MCP_STDIO_STATE_DIR` 后需重新运行 `install` 或 `update --hooks`。

安装器拒绝符号链接配置和有歧义的输入。`install` 设置新的启动参数；已有参数需要保留时使用 `update`。

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
.venv/bin/python -m pip install -e '.[nexus,gui]'
.venv/bin/ida-mcp-server install --client all --backend nexus \
  --ida-dir '/Applications/IDA Professional 9.4.app/Contents/MacOS' \
  --gui-plugin --gui-create-environment --hooks
```

`--gui-plugin` 调用官方 HCLI 检查 IDAPython 并部署官方 GUI provider。`--gui-create-environment` 明确允许 HCLI 创建环境、配置登录环境变量；已有 GUI venv 时改用 `--gui-python /absolute/gui-venv/bin/python`。服务 Python 和 GUI Python 可以分别配置。

添加 `--dry-run` 预览全部命令，不运行 HCLI、不写配置。`--venv` 可在一次安装中创建服务环境并安装 GUI extra。需要选择其他 HCLI、IDA 用户目录或 GUI venv 位置时，使用 `--gui-hcli`、`--gui-ida-user-dir`、`--gui-environment`。`--gui-no-configure-environment` 只创建环境，启动 GUI 时需自行设置 `IDAPYTHON_VENV_EXECUTABLE`。

当前官方 GUI 插件需要 IDA 9.4+、Python 3.11+ 和 Nexus 0.13.4+。部署前会校验全部客户端配置。HCLI 的包安装和登录配置由 HCLI 管理；失败时保留诊断，已完成的外部修改可能仍存在。

按 HCLI 输出配置 `IDAPYTHON_VENV_EXECUTABLE`，让 IDA GUI 使用已安装插件依赖的 Python 环境。已启动的 GUI 不会自动获得终端环境变量。修改后重启 IDA，并在启动日志中检查 Python 路径。

## Codex / Claude Code 插件

插件安装和直接 MCP 配置任选一种，避免重复注册同一服务。插件需要客户端 PATH 中有 `python3`，并通过 `IDA_MCP_STDIO_PYTHON` 指定已安装本项目的解释器；也可使用插件目录的 `.venv` 或客户端插件数据目录下的 `venv`。

```sh
export IDA_MCP_STDIO_PYTHON='/absolute/path/ida-mcp-stdio/.venv/bin/python'
claude plugin marketplace add /absolute/path/ida-mcp-stdio
claude plugin install ida-mcp-stdio@ida-mcp-stdio-local

codex plugin marketplace add /absolute/path/ida-mcp-stdio
codex plugin add ida-mcp-stdio@ida-mcp-stdio-local
```

两种客户端共用 `.claude-plugin/marketplace.json`，Codex 使用其兼容清单格式。插件目录被复制到缓存时仍应设置绝对 Python 路径。`IDA_MCP_STDIO_BACKEND=nexus` 可切换插件启动器的后端，默认 native；Nexus 依赖需安装到指定解释器环境。`IDADIR` 选择 IDA，`IDA_MCP_STDIO_STATE_DIR` 选择状态目录。

清单默认启用会话日志。插件中的 hooks 仍需按客户端机制审阅；插件安装不升级所选 Python 环境的包。仅使用插件时，用指定解释器的 pip 升级本项目；`update` 适用于直接 MCP 配置，会同时刷新配置文件。插件文件通过客户端的插件更新功能更新。PyPI 发布配置见[发布说明](RELEASING.md)。

## 验证与排错

- 修改配置后重新加载 MCP 或开启新会话；桌面应用可能需要重启。
- 连接后应发现六个 compact 工具；调用 `reference` 可以在不开库时检查服务。
- 再调用 `open_database`，执行 `import ida_kernwin; ida_kernwin.get_kernel_version()` 确认实际 IDA 版本。
- 开库慢时，检查客户端的工具超时设置。执行默认上限为 360 秒，示例中的客户端超时为 420 秒。
- 连接失败时先运行 `.venv/bin/ida-mcp-server --doctor`，检查 Python 环境、安装目录、Nexus launcher 与客户端 stderr 日志。

`--print-config` 只打印通用 `mcpServers` JSON，不写文件。用 `install` 可直接写入各客户端的配置格式。
