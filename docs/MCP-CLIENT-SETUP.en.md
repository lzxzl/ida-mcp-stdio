# MCP client setup

[中文](MCP-CLIENT-SETUP.md)

Install the project using the [README](../README.en.md). Replace `/absolute/path/ida-mcp-stdio` below with your repository path. Use an absolute Python path so the client's PATH or a global package of the same name does not select another environment.

## Install and update commands

Write all five client configurations for the current environment:

```sh
.venv/bin/ida-mcp-server install --client all --python "$PWD/.venv/bin/python" \
  --backend nexus --ida-dir '/Applications/IDA Professional 9.4.app/Contents/MacOS' \
  --session-log auto --hooks
```

Add `--dry-run` to inspect planned settings without changing files. Select individual clients with `--client codex zcode`. Install preserves unrelated settings; `update` refreshes existing Claude project overrides of the same server name. Originals are backed up under `~/.local/state/ida-mcp-stdio/backups/` before writes. JSONC comments/trailing commas and ambiguous configurations are rejected; use the manual examples below for those files.

To create a private installation from GitHub main:

```sh
.venv/bin/ida-mcp-server install --venv --backend nexus --client all
# Upgrade the current venv and refresh configs
.venv/bin/ida-mcp-server update --client all
```

`--venv` defaults to `~/.local/share/ida-mcp-stdio/venv`; an explicit path selects another environment. `--source` selects a package/repository source. Update requires a venv and upgrades it before writing configs. It preserves existing startup arguments, transport, enabled state, timeouts and other settings; only explicitly supplied flags override them. Existing same-name Claude project entries are refreshed with their own arguments retained. `install` without `--venv` or `--gui-plugin` only writes configs; its defaults are native, compact and automatic session logs.

The default source is remote main. To try local changes before pushing them, add `--source /absolute/path/ida-mcp-stdio` so the installer uses the current checkout.

`--idle-timeout SECONDS` opts into Nexus lease expiry; `0` disables it. `--hooks` adds current-session correlation for Claude Code, supported Codex CLI, OpenCode and ZCode. It preserves unrelated hooks and existing disabled settings. Codex must have its stable hooks capability enabled and requires `/hooks` review; the installer does not change feature flags. Codex Windows hooks need manual setup. Reload MCP to use an updated package.

OpenCode installs a local plugin at `~/.config/opencode/plugins/ida-mcp-stdio.js`, using the tested V1 contract (OpenCode 1.15.13, SDK 1.14.40). ZCode uses `hooks.events`; check that hooks are enabled in Settings. ZCode 3.14.5 temporary transcripts contain the current prompt or final response; the durable record also contains related IDA tool events. Missing usage stays unavailable. Claude Desktop has no supported automatic transcript interface; link an exported file explicitly. OpenCode / ZCode snapshot paths are fixed at installation; rerun `install` or `update --hooks` after changing `IDA_MCP_STDIO_STATE_DIR`.

The installer rejects symlinked configurations and ambiguous inputs. `install` sets new launch arguments; use `update` to preserve existing arguments.

## Choosing a backend

The configurations below use `--backend native`, which always runs headless and supports IDA 9.2 / 9.4. For a GUI or sharing across clients on 9.4+, install `.[nexus]` and switch to `--backend nexus`. Nexus starts a headless worker when it cannot find a matching instance.

To select an IDA version, append two elements to the args / command array: `"--ida-dir"` and the installation path. On macOS, for example, use `/Applications/IDA Professional 9.4.app/Contents/MacOS`. You can also set `IDADIR`.

## Codex

Edit `~/.codex/config.toml`:

```toml
[mcp_servers.ida-mcp-stdio]
command = "/absolute/path/ida-mcp-stdio/.venv/bin/python"
args = ["-u", "-m", "ida_mcp_stdio", "--backend", "native", "--tool-profile", "compact", "--agent", "codex"]
enabled = true
startup_timeout_sec = 30
tool_timeout_sec = 420
```

Inspect the configuration with `codex mcp get ida-mcp-stdio --json`. This command shows configuration; it does not test the connection. See the [Codex configuration documentation](https://developers.openai.com/codex/mcp/).

## Claude Code

Add a user-level server with the CLI:

```sh
claude mcp add --scope user --transport stdio ida-mcp-stdio -- \
  /absolute/path/ida-mcp-stdio/.venv/bin/python -u -m ida_mcp_stdio \
  --backend native --tool-profile compact --agent claude-code
```

You can also merge the entry into `mcpServers` in `~/.claude.json`. Update an existing entry of the same name, and check whether the current project has an override.

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

Check with `claude mcp get ida-mcp-stdio`. See the [Claude Code configuration documentation](https://code.claude.com/docs/en/mcp).

## Claude Desktop

On macOS, the configuration is at `~/Library/Application Support/Claude/claude_desktop_config.json`. Merge this entry into the existing `mcpServers` object:

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

Restart Claude Desktop after saving. On other platforms, open the configuration file through the application's settings.

## OpenCode

Merge the entry into `mcp` in `~/.config/opencode/opencode.json`:

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

Check with `opencode mcp list`. The example uses the tested OpenCode 1.15 configuration format. See the [OpenCode configuration documentation](https://opencode.ai/docs/mcp-servers/).

## ZCode

Merge the entry into `mcp.servers` in `~/.zcode/cli/config.json`:

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

ZCode enables servers by default. Reload MCP, then check the connection status in the application's MCP management screen. See the [ZCode configuration documentation](https://zcode.z.ai/en/docs/mcp-services) and [CLI field documentation](https://github.com/zai-org/ZCode/blob/main/apps/zcode-cli/README.md#mcp-configuration).

## Nexus / GUI environment

Install the Nexus launcher in the Python environment used by the MCP server. An `ida-nexus` executable from another environment will not be used, even if it is on PATH.

```sh
.venv/bin/python -m pip install -e '.[nexus,gui]'
.venv/bin/ida-mcp-server install --client all --backend nexus \
  --ida-dir '/Applications/IDA Professional 9.4.app/Contents/MacOS' \
  --gui-plugin --gui-create-environment --hooks
```

`--gui-plugin` invokes official HCLI to check IDAPython and deploy the official GUI provider. `--gui-create-environment` permits HCLI to create a venv and configure its login environment. To select an existing GUI venv, use `--gui-python /absolute/gui-venv/bin/python` instead. Server Python and GUI Python can be configured separately.

Add `--dry-run` to preview all commands without running HCLI or writing configuration. `--venv` can create the server environment and install the GUI extra in one operation. Use `--gui-hcli`, `--gui-ida-user-dir` and `--gui-environment` to select other paths. `--gui-no-configure-environment` creates only the venv; select it with `IDAPYTHON_VENV_EXECUTABLE` when starting IDA.

The current official GUI plugin needs IDA 9.4+, Python 3.11+ and Nexus 0.13.4+. All client configurations are validated before deployment. HCLI owns package and login configuration changes; failures retain diagnostics and may leave completed external changes.

Follow the HCLI output to configure `IDAPYTHON_VENV_EXECUTABLE` so the GUI uses the Python environment containing the plugin dependencies. A running GUI does not automatically receive terminal environment variables. Restart IDA after making changes and check the Python path in its startup log.

## Codex / Claude Code plugins

Use either plugin registration or direct MCP configuration to avoid registering the same server twice. Plugins need `python3` on the client PATH and `IDA_MCP_STDIO_PYTHON` pointing to an interpreter with this project installed. A `.venv` at the plugin root or a `venv` in the client's plugin data directory can also be used.

```sh
export IDA_MCP_STDIO_PYTHON='/absolute/path/ida-mcp-stdio/.venv/bin/python'
claude plugin marketplace add /absolute/path/ida-mcp-stdio
claude plugin install ida-mcp-stdio@ida-mcp-stdio-local

codex plugin marketplace add /absolute/path/ida-mcp-stdio
codex plugin add ida-mcp-stdio@ida-mcp-stdio-local
```

Both clients use `.claude-plugin/marketplace.json`, through Codex's compatible catalog format. Keep an absolute Python path when the plugin is copied into a cache. `IDA_MCP_STDIO_BACKEND=nexus` selects Nexus in the plugin launcher; the default is native. Install Nexus dependencies in the selected interpreter environment. `IDADIR` selects IDA, and `IDA_MCP_STDIO_STATE_DIR` selects the state directory.

Manifests enable session traces. Review hooks through the client's normal controls. Installing a plugin does not upgrade the selected Python environment. For plugin-only installations, upgrade this project through the selected interpreter's pip; `update` also refreshes direct MCP configurations. Use the client's plugin update mechanism for plugin files. See [releases](RELEASING.en.md) for PyPI setup.

## Verification and troubleshooting

- Reload MCP or start a new session after changing configuration. Desktop applications may need a restart.
- A connected server should list six compact tools. Call `reference` to check the server without opening a database.
- Call `open_database`, then run `import ida_kernwin; ida_kernwin.get_kernel_version()` to confirm the actual IDA version.
- If opening a database is slow, check the client's tool timeout. Execution defaults to 360 seconds; the examples give the client 420 seconds.
- If connection fails, run `.venv/bin/ida-mcp-server --doctor` and check the Python environment, installation directory, Nexus launcher, and the client's stderr log.

`--print-config` prints generic `mcpServers` JSON without writing files. Use `install` to write each client's own format.
