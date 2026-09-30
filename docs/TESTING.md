# 测试与验证范围

## 自动化测试

```sh
.venv/bin/python -m pip install -e '.[dev,nexus,http]'
.venv/bin/python -m pytest tests -q

# 启用真实 IDA；本机 macOS 示例
IDADIR='/Applications/IDA Professional 9.4.app/Contents/MacOS' \
AI4BA_IDA_MCP_TESTS=1 .venv/bin/python -m pytest tests -v

# 覆盖率
.venv/bin/python -m pytest tests --cov=ida_mcp_stdio --cov-report=term-missing
```

无需 IDA 的测试覆盖协议、参数校验、代码执行、数据库路由、取消、artifact 分页、会话隔离、客户端和 mock 分析 helper。真实用例需要 IDA 许可、反编译器与 clang；样本在临时目录生成。

`test_backend_real_ida.py` 当前按 macOS 安装路径参数化 native 9.2、native 9.4、Nexus 9.4。`IDADIR` 控制结构化事实真实用例使用的版本。未安装对应环境时相关用例会跳过。

## 已验证环境

2026-09-30：macOS、Python 3.14.2、IDA Professional 9.2 / 9.4、ida-nexus 0.13.0、ida-domain 0.5.1、MCP SDK 1.26.0。

| 发布前检查 | 结果 |
| --- | --- |
| 完整 pytest，启用真实 IDA，IDADIR=9.2 | 137 passed，无 skip |
| 完整 pytest，启用真实 IDA，IDADIR=9.4 | 137 passed，无 skip |
| Black、Ruff、Git 空白检查 | 通过 |
| wheel 构建与无 site-packages 的 stdio 握手 / reference | 通过 |
| 五个保留示例的实机运行 | 全部正常退出 |

- 两版 IDA 均通过无头开库、执行、原生 stdout 隔离、持久 / 临时上下文、await、保存与关闭。
- C++ 带符号和部分 strip 样本均通过结构化事实往返。
- IDA 9.4 GUI：两个独立 MCP 客户端共享 owner，主线程执行，改名 / 注释同步、反编译、保存、租约释放通过；官方 DatabaseHandle 收到 IDB 事件。
- Nexus 无头 worker 异常退出后重新开库，恢复已保存 checkpoint。
- Codex、Claude Code / Desktop、OpenCode、ZCode 的配置命令均通过真实 MCP SDK 握手和工具调用；Claude Code、OpenCode、ZCode 自身报告 connected。

pytest 覆盖率只统计被注入 coverage 的进程，不能代表独立 worker 和 GUI 的覆盖率。未验证未来 IDA 版本、真实网络文件系统、远程多人部署及所有异常退出组合。
