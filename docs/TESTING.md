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

### 0.5，2026-10-11 / 12

本次环境为 macOS、Python 3.14，用户配置和 IDA 插件目录只读，本地端口绑定受限。

- 完整本地 suite：414 passed、7 skipped、4 failed。四项失败均为 HTTP / 实时看板的 localhost 绑定被环境拒绝；七项默认未启用的 IDA 用例跳过。
- native 9.2 / 9.4 开库、执行、持久上下文、保存和关闭均通过；两版带符号和部分 strip C++ 的结构化事实往返各通过两项。
- 固定 C 样本的 batch / separate 基准在两版 IDA 上返回一致事实，工作流请求分别为 1 / 3；未运行模型推理用量基准。
- 42 项 GUI 适配测试通过。真实 HCLI 0.26.2 doctor 检查通过，但隔离目录无法确认嵌入 Python；没有完成新的 GUI provider 部署验证。
- OpenCode 1.15.13 / SDK 1.14.40 的实际 V1 客户端接口通过注入 fetch 验证。ZCode 3.14.5 hook 合同与临时转录机制按本机代码检查，保存、并发和配置测试通过；没有进行新模型会话验证。
- Claude 2.1.267 严格插件验证、隔离 Codex marketplace 安装及实际插件 stdio 握手通过。wheel / sdist 构建和离线安装通过；Twine、外部发布及用户级配置写入受本次环境限制。

实机 native 验证使用临时 `IDAUSR`，保留用户已有的许可接受状态；artifact 与日志使用临时状态目录。新的 Nexus extra 下限为 0.13.4，本机已安装 0.13.0，不能把下面的旧版共享验证当成本次 0.13.4 的实机结果。Windows、Linux 和其他 IDA 产品版本仍未完成实机验证。

### 0.4，2026-09-30

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
