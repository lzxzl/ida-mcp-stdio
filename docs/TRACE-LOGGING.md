# 日志、看板与导出

[English](TRACE-LOGGING.en.md)

## 记录日志

运行日志默认写入 stderr。`--verbose` 开启 DEBUG，`--log-level TRACE` 包含协议细节，`--log-file` 指定文件。TRACE 未指定路径时使用 `~/.codex/log/ida-mcp-<timestamp>.log`。

JSONL 会话记录按需开启：

```sh
.venv/bin/ida-mcp-server --agent codex --session-log auto
# 或指定文件
.venv/bin/ida-mcp-server --session-log /path/to/session.jsonl
```

`auto` 写入 `~/.local/state/ida-mcp-stdio/<session-id>.jsonl`。记录包含初始化、工具参数、结果、错误、耗时和 Nexus 生命周期事件。新建状态目录权限为 0700，文件为 0600。记录失败会输出警告，不改变已完成工具的结果。

## 会话看板

```sh
.venv/bin/ida-mcp-server dashboard --open
# 指定其他记录目录
.venv/bin/ida-mcp-server dashboard --state-dir /path/to/traces --port 8740
# 导出单个会话的独立 HTML
.venv/bin/ida-mcp-server dashboard --session /path/to/session.jsonl \
  --export /path/to/session.html
```

实时看板仅监听回环地址，刷新本地会话，支持搜索、客户端和事件筛选，显示工具延迟、错误以及 MCP 与客户端合并时间线。HTML 导出包含选定会话及其关联转录，不加载外部资源。原有 `--dashboard JSONL --output HTML` 命令仍可使用。

## 关联客户端转录

用 `install --hooks` 安装 Claude Code 和支持 hooks 的 Codex CLI 适配。Codex 新增或修改 hook 后，需要在 `/hooks` 中审阅信任才会运行。Hook 将转录路径放入工具输入的 `_meta`，服务端在参数校验和执行前将其移除。

解析器支持 Claude、Codex、Copilot、OpenCode 和 ZCode 的记录格式。Copilot 可使用 `hook copilot`；自动安装 hooks 的范围是 Claude Code 和 Codex。其他客户端可通过 `_meta` 提供会话路径，例如 Python 客户端：

```python
client.call_tool("reference", {"query": "decompile"}, metadata={
    "codex_session_path": "/absolute/path/rollout.jsonl"
})
```

使用对应的 `<agent>_session_path` 键，Claude Code 使用 `claude_session_path`。看板只读取明确关联的转录，不扫描客户端历史。Token 和费用取自记录字段，缺失费用显示无记录；Codex 累计用量采用最新检查点。用量覆盖整个关联转录，可能包含本服务之外的操作；不同 MCP 会话关联同一转录时会有重叠。任务时间按记录中的活动区间计算，会话耗时为首末记录之间的时间。

## 导出 ZIP

```sh
.venv/bin/ida-mcp-server logs --output /path/to/ida-mcp-logs.zip
# 只导出一个会话，排除客户端转录
.venv/bin/ida-mcp-server logs --session /path/to/session.jsonl \
  --no-transcripts --output /path/to/one-session.zip
```

ZIP 包含选定会话的原始记录、引用的结果文件和关联转录。`ida-mcp-logs.json` 列出原路径、归档路径、大小、SHA-256 及文件缺失、记录跳过的警告。目标文件已存在时拒绝覆盖，新归档权限为 0600。分享前检查内容，归档保留分析数据和对话。

## 大结果与清理

超过 `--inline-limit`（默认 65536 字节）的结果保存在 `~/.local/state/ida-mcp-stdio/<session-id>/`，响应带路径和资源 URI。分页方法见[使用指南](使用指南.md)。

服务退出后文件仍然保留，使用完毕可删除对应 JSONL 和会话目录。结果文件保存执行器捕获的内容，超出执行器捕获上限的输出无法恢复。日志、导出和分析结果不要提交 Git。
