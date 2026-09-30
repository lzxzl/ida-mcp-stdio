# 架构与传输

## native：纯无头

```text
MCP 客户端
    ↕ stdio JSON-RPC
MCP 服务进程：协议、工具注册、实例路由、结果与日志
    ├─ worker A：idalib / IDAPython / IDB A
    ├─ worker B：idalib / IDAPython / IDB B
    └─ worker C：idalib / IDAPython / IDB C
```

每个数据库在独立子进程的主线程中运行 IDA。父进程不加载 IDA。同一 worker 内请求串行；数据库之间拥有独立上下文和故障边界。stdio 服务逐个处理工具调用，多库并存不等于单连接并行调度。

worker 在导入 IDA 前分离协议输出描述符，将原生 stdout 转到 stderr。Python stdout / stderr 由执行器捕获后放入 JSON，避免日志破坏协议。

native 不跨 MCP 服务共享 IDB。多个服务同时打开同一 IDB 可能产生锁竞争；需要共享时使用 Nexus。

## Nexus：官方实例与 GUI 共享

```text
MCP 客户端 ↔ stdio 服务 ↔ ida_nexus.DatabaseManager
                              ├─ 已存在的 GUI / 无头实例
                              └─ 新建的无头 worker
```

本项目通过官方公共 Manager API 取得数据库租约、执行代码、保存和释放连接。GUI 操作由官方插件切换到 IDA 主线程。共享同一 IDB 的客户端可以看到彼此的修改；释放一个租约不代表关闭 GUI。

实例发现、认证、事件与崩溃恢复由 Nexus 提供。MCP 的六个默认工具没有单独的事件订阅接口；本次事件验证通过官方 `DatabaseHandle` 完成。

Nexus 0.13.0 在 macOS 的网络文件系统探测存在 ABI 问题。本项目只在该版本和平台的服务进程内修正 `statfs` 符号绑定，保留官方网络盘限制。

## stdio

每行一个 JSON-RPC 2.0 消息，stdout 为协议通道，stderr 为日志。连接包含初始化、工具发现 / 调用、资源读取和取消通知。支持的协议版本是 2024-11-05、2025-03-26、2025-06-18、2025-11-25。

一个 stdio 服务对应一个客户端连接。不同客户端各自启动服务；跨服务共享由 Nexus 实现。`IDAMCPClient` 通过双向子进程管道连接，不使用 HTTP。

## 可选 Streamable HTTP

```sh
.venv/bin/python -m pip install -e '.[http]'
.venv/bin/ida-mcp-server --transport http --backend native \
  --host 127.0.0.1 --port 8737
```

MCP 地址为 `http://127.0.0.1:8737/mcp/`。使用官方 MCP Python SDK；各 HTTP 会话具有独立数据库管理器、当前选择和 artifact 索引。Nexus 仍可能让这些会话共享底层 IDB。

HTTP 仅允许 loopback 地址，启用 Host / Origin 检查；没有远程访问鉴权。需要远程部署时，应在外层提供认证代理。Nexus 内部认证不覆盖 MCP HTTP 接口。
