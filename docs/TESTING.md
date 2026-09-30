# 测试与验证范围

[English](TESTING.en.md)

## 自动化测试

测试目录仅保留在本地，不随 Git 发布。以下命令供已有本地测试目录的开发环境使用。

```sh
.venv/bin/python -m pip install -e '.[dev,nexus,http]'
.venv/bin/python -m pytest tests -q

# 启用真实 IDA；本机 macOS 示例
IDADIR='/Applications/IDA Professional 9.4.app/Contents/MacOS' \
AI4BA_IDA_MCP_TESTS=1 .venv/bin/python -m pytest tests -v

# 覆盖率
.venv/bin/python -m pytest tests --cov=ida_mcp_stdio --cov-report=term-missing
```

无需 IDA 的测试覆盖协议、参数校验、代码执行、数据库路由、取消、artifact 分页、会话隔离、客户端和 mock 分析 helper。真实 IDA 用例需要 IDA 许可、反编译器和 clang，样本在临时目录中生成。

`test_backend_real_ida.py` 按 macOS 安装路径分别验证 native 9.2、native 9.4、Nexus 9.4。`IDADIR` 控制结构化事实真实用例使用的版本。缺少对应环境时，相关用例会跳过。

## 已验证环境

2026-09-30：macOS、Python 3.14.2、IDA Professional 9.2 / 9.4、ida-nexus 0.13.0、ida-domain 0.5.1、MCP SDK 1.26.0。

| 发布前检查 | 结果 |
| --- | --- |
| 完整 pytest，启用真实 IDA，IDADIR=9.2 | 293 passed，无 skip |
| 完整 pytest，启用真实 IDA，IDADIR=9.4 | 293 passed，无 skip |
| Black、Ruff、Git 空白检查 | 通过 |
| wheel 构建与无 site-packages 的 stdio 握手 / reference | 通过 |
| 六个示例的实机运行 | 全部正常退出 |

- 两版 IDA 均通过无头开库、执行、原生 stdout 隔离、持久和临时上下文、await、保存与关闭。
- C++ 带符号和部分 strip 样本均通过结构化事实往返。
- IDA 9.4 GUI 中，两个独立 MCP 客户端共享 owner，代码在主线程执行。改名和注释同步、反编译、保存、租约释放均通过，官方 DatabaseHandle 也收到了 IDB 事件。
- Nexus 无头 worker 异常退出后重新开库，恢复已保存 checkpoint。
- Codex、Claude Code / Desktop、OpenCode、ZCode 的配置命令均通过真实 MCP SDK 握手和工具调用；Claude Code、OpenCode、ZCode 自身报告 connected。

- Domain 0.5.1 离线索引与官方的 1,621 个公开 API 名称对齐，包含全部 33 个完整示例，查询不导入 IDA。
- Nexus 无头实机测试覆盖空闲释放、其他客户端租约保留、最后一次 checkpoint 保存与立即重开；GUI 在租约到期和释放后继续运行。
- HTTP 使用真实 SDK 传输和注入的生命周期事件，验证日志级别、元数据隔离，以及首次业务请求之前的断连通知。
- Chrome 验证搜索、筛选、刷新和离线 HTML。ZIP 测试排除元数据中伪造的 artifact，保留原始损坏记录；异常和溢出的用量显示不可用并附警告。
- 客户端安装器测试覆盖五种格式、备份、项目覆盖项、自定义参数和超时、不支持的启动器、私有 venv 更新；临时 venv 的真实安装与更新通过。

pytest 覆盖率只统计注入了 coverage 的进程，不能据此推断独立 worker 和 GUI 的覆盖率。未来 IDA 版本、真实网络文件系统、远程多人部署和所有异常退出组合尚未验证。
