# 更新记录

[English](CHANGELOG.en.md)

## 0.3.0

- 拆分 stdio 服务与 IDA owner，每个数据库独立运行，支持实例路由、超时和取消。
- 新增六工具 compact 入口、组合 Python 执行、持久上下文、await 和离线 API 查询。
- 大结果保存为完整 artifact，支持分页读取。新增 JSONL 会话记录和 HTML 导出。
- 新增官方 Nexus 后端，支持 IDA 9.4+ 无头 / GUI 共享；native 保留 IDA 9.2 支持。
- 新增可选 Streamable HTTP，每会话独立路由和结果索引。
- 扩展分析 helper 与结构化事实接口，增加 Python 客户端封装和本地回归测试。
- 修正 Nexus 0.13.0 在 macOS 的 statfs ABI 探测。
