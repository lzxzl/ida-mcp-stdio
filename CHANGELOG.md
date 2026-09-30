# 更新记录

[English](CHANGELOG.en.md)

## 0.4.0

- 补齐离线 Domain 查询：模块、装饰器、继承关系、版本，以及独立示例搜索和完整源码。
- 新增 Nexus `--idle-timeout`，空闲时释放本会话的无头租约；处理最后一个实例保存期间的重新开库过渡。
- 记录 Nexus 生命周期事件，通过 MCP logging 发送断连警告；Python 客户端可读取通知。
- 新增多会话本地看板、对话记录关联、记录中的 token / 费用统计，以及日志、artifact 和关联对话的 ZIP 导出。
- 新增 `install` / `update`：备份并更新 Codex、Claude Code / Desktop、OpenCode、ZCode 配置，支持私有虚拟环境、预览和 hook 安装。
- 保留旧启动命令，新增 `stdio`、`http`、`dashboard`、`logs`、`hook` 子命令。
- 新增 legacy / compact 等价工作流对比示例，输出请求数、耗时、载荷字节及可选 tokenizer 计数。

## 0.3.0

- 拆分 stdio 服务与 IDA owner，每个数据库独立运行，支持实例路由、超时和取消。
- 新增六工具 compact 入口、组合 Python 执行、持久上下文、await 和离线 API 查询。
- 大结果保存为完整 artifact，支持分页读取。新增 JSONL 会话记录和 HTML 导出。
- 新增官方 Nexus 后端，支持 IDA 9.4+ 无头 / GUI 共享；native 保留 IDA 9.2 支持。
- 新增可选 Streamable HTTP，每会话独立路由和结果索引。
- 扩展分析 helper 与结构化事实接口，增加 Python 客户端封装和本地回归测试。
- 修正 Nexus 0.13.0 在 macOS 的 statfs ABI 探测。
