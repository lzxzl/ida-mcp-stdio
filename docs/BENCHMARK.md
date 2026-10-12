# 任务基准

[English](BENCHMARK.en.md)

## 重复同一分析任务

`benchmark run` 使用 IDAPython 查询前 32 个函数、前 32 个字符串和最多 64 个导入。每个函数最多扫描 256 个地址项，采样其中的调用关系。`separate` 分三次调用，`batch` 在一次 Python 调用中完成同样的查询。

运行时复制输入二进制到临时目录，在副本上创建、保存和关闭数据库，原文件保持原样。输入应是可执行文件或库，已有 IDB 不适用于这个基准。

```sh
clang -O0 -g examples/benchmark_sample.c -o /tmp/ida-mcp-sample
.venv/bin/ida-mcp-server benchmark run /tmp/ida-mcp-sample \
  --label separate --mode separate --output /tmp/separate.json
.venv/bin/ida-mcp-server benchmark run /tmp/ida-mcp-sample \
  --label batch --mode batch --output /tmp/batch.json
.venv/bin/ida-mcp-server benchmark compare /tmp/separate.json /tmp/batch.json \
  --output /tmp/comparison.json
```

用 `--ida-dir` 固定 IDA 安装，`--backend nexus` 选择共享后端。输出文件权限为 0600，目标已存在时拒绝覆盖。任务和环境分别记录二进制 SHA-256、查询代码 SHA-256、服务版本、IDA / Python 版本与文件类型。

比较要求代码、二进制、主机与 Python / IDA 环境、工具 profile、实际工具集合和返回事实全部一致。报告记录双方的 schema 摘要及其是否一致；工具描述或 schema 内容可以不同。指标包括工作流请求数、耗时和 JSON 返回字节，字节数不含传输 framing。耗时包含 MCP 执行与传输，应多次运行并交替顺序，避免把缓存和调度差异当成提升。

2026-10-11 在 IDA 9.2、9.4 native 后端上，样本的两种执行方式都返回相同事实，工作流调用数分别为 3 和 1。这个结果没有测量智能体推理用量，也未复现官方约 20% token 节省基准。

## 比较其他 stdio 服务

将启动命令保存为 JSON 数组，例如 `/path/to/official-command.json`：

```json
["/absolute/official/venv/bin/ida-mcp", "stdio", "--agent", "benchmark"]
```

```sh
.venv/bin/ida-mcp-server benchmark run /path/to/sample \
  --label official --server-command /path/to/official-command.json \
  --output /path/to/official-report.json
```

该命令需支持 `open_database(path)`、`execute_python(code, instance_id, timeout)` 和 `close_database(instance_id)`。数组直接启动子进程，不经 shell；外部服务的安装、环境和启动参数由调用方配置。

## 读取实际智能体用量

```sh
.venv/bin/ida-mcp-server benchmark usage /path/to/transcript.jsonl \
  --agent codex --output /path/to/usage.json
```

支持 Claude、Codex、OpenCode 和 ZCode 解析器。用量取自整份指定转录，可能包含其他工具或任务；缺失 token / 费用保持不可用。比较智能体时，应使用独立新会话、相同模型、提示词和样本，并检查任务是否正确完成。脚本耗时、schema tokenizer 计数和模型实际计费分别记录。
