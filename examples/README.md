# 示例

[English](README.en.md)

安装项目并配置 IDA 后，使用项目虚拟环境运行示例。请自行准备样本，仓库不包含 IDA 数据库或大型二进制。

| 示例 | 命令 | 内容 |
| --- | --- | --- |
| 基础调用 | `.venv/bin/python examples/basic_usage.py /path/to/binary` | 函数列表与反编译 |
| 多库组合分析 | `.venv/bin/python examples/code_mode.py /path/to/a /path/to/b` | compact 工具、reference、instance_id 路由 |
| 函数分页 | `.venv/bin/python examples/pagination_example.py /path/to/binary` | 按页读取函数 |
| 顺序批量分析 | `.venv/bin/python examples/batch_analysis.py /path/to/a /path/to/b` | 每个样本完成后关闭数据库 |
| 工具模式对比 | `.venv/bin/python examples/compare_tool_profiles.py /path/to/binary` | 等价结果、请求数、载荷字节和耗时；可选 `--encoding o200k_base` |
| 会话日志 | `.venv/bin/python examples/trace_logging_example.py /path/to/binary` | 生成 JSONL 记录 |

示例使用默认的 native 无头后端。需要指定 IDA 版本时，先设置 `IDADIR`，或在客户端 `server_args` 中传入 `--ida-dir`。自动化测试保留在本地的 `tests/`，不随 Git 发布。
