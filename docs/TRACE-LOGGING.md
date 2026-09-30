# 日志与结果文件

## 运行日志

默认写入 stderr。`--verbose` 启用 DEBUG，`--log-level TRACE` 记录详细协议消息。指定 `--log-file` 写文件；TRACE 未指定路径时写入 `~/.codex/log/ida-mcp-<时间戳>.log`。

```sh
.venv/bin/ida-mcp-server --log-level DEBUG --log-file /path/to/server.log
```

运行日志可能包含工具参数与分析数据。日志文件不应提交到 Git。

## JSONL 会话记录

默认关闭。启用后按请求记录工具参数、结果或错误、耗时、会话 ID 和 agent 标签。

```sh
.venv/bin/ida-mcp-server --agent codex --session-log auto
# 或指定路径
.venv/bin/ida-mcp-server --session-log /path/to/session.jsonl
```

`auto` 写入 `~/.local/state/ida-mcp-stdio/<随机ID>.jsonl`，启动日志打印路径。自动创建的目录权限为 0700，日志文件为 0600。记录失败会报警，但不会将已完成的业务操作改成失败。

导出可搜索的本地 HTML：

```sh
.venv/bin/ida-mcp-server --dashboard /path/to/session.jsonl \
  --output /path/to/session.html
```

HTML 包含记录内容，不加载外部资源。

## 大结果 artifact

默认内联上限为 65536 字节，可用 `--inline-limit` 调整。超限完整结果保存到 `~/.local/state/ida-mcp-stdio/<会话ID>/`，文件权限 0600；响应包含路径和资源 URI。

文件在会话结束后保留，不自动清理。确认不再需要时，可删除对应 JSONL 和会话目录。artifact 保存的是执行器已捕获的结果，不能恢复超过 stdout / stderr 捕获上限的内容。分页读取见[使用指南](使用指南.md)。
