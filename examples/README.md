# 示例

先安装项目并配置 IDA，使用项目虚拟环境执行。样本需自行提供；仓库不分发 IDA 数据库或大型二进制。

| 示例 | 命令 | 内容 |
| --- | --- | --- |
| 基础调用 | `.venv/bin/python examples/basic_usage.py /path/to/binary` | 函数列表与反编译 |
| 多库组合分析 | `.venv/bin/python examples/code_mode.py /path/to/a /path/to/b` | compact 工具、reference、instance_id 路由 |
| 函数分页 | `.venv/bin/python examples/pagination_example.py /path/to/binary` | 按页读取函数 |
| 顺序批量分析 | `.venv/bin/python examples/batch_analysis.py /path/to/a /path/to/b` | 每个样本完成后关闭数据库 |
| 会话日志 | `.venv/bin/python examples/trace_logging_example.py /path/to/binary` | 生成 JSONL 记录 |

这些脚本使用默认 native 无头后端。指定 IDA 版本可先设置 `IDADIR`，或在客户端 `server_args` 中传入 `--ida-dir`。正式自动化测试位于 `tests/`。
