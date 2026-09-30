# 数据库管理

[English](DATABASE-MANAGEMENT.en.md)

## 工具参数

| 工具 | 参数 | 行为 |
| --- | --- | --- |
| `open_database` | `path` 或兼容参数 `binary_path`；`set_current=true`；`force_reanalyze=false` | 打开二进制或 IDB，返回 `instance_id` |
| `list_databases` | 无 | native 返回自身持有实例；Nexus 还返回本机可发现实例 |
| `save_database` | `instance_id` 可选 | 保存指定或当前 IDB |
| `close_database` | `instance_id` 可选；`save=true` | native 保存并关闭 worker；Nexus 保存并释放租约 |

打开新库会保留已有库。native 的 `set_current=false` 会保持当前选择。Nexus 已有当前目标时也会保持原选择；没有当前目标时，则会选中新开的库。`execute_python(instance_id=...)` 可访问任一持有实例。直接调用分析工具时，使用当前数据库。

## 多库示例

```python
from ida_mcp_stdio import IDAMCPClient

with IDAMCPClient(tool_profile="compact") as client:
    client.initialize()
    left = client.open_database("/path/to/main.so")
    right = client.open_database("/path/to/helper.so", set_current=False)
    for target in (left, right):
        report = client.execute_python(
            "tools.list_funcs(count=5)", instance_id=target["instance_id"]
        )
        print(target["path"], report["result"])
        client.close_database(target["instance_id"])
```

native 会规范化路径，复用同一服务内已经打开的目标。默认最多四个活跃 worker，可用 `--max-workers` 调整。达到上限后会拒绝新库，需要先关闭已有目标。

Nexus 列表中 `available` / `unavailable` 条目可能尚未被当前会话持有，`instance_id` 为 null。用条目的 `path` 调用 `open_database`，取得当前会话的实例 ID 后，再执行或关闭。`current` / `attached` 表示已有租约。

## 保存与重建

正常关闭或服务收到 EOF 时，会尝试保存并回收数据库。重要修改后应调用 `save_database`，以免异常退出丢失数据。

native 可用 `close_database(save=False)` 在关闭时跳过保存。这个选项不能撤销其他文件写入，也不能限制代码的写入权限。Nexus 共享 IDB，拒绝 `save=False`。

`force_reanalyze=true` 仅 native 支持。先关闭该活跃目标，再传入原始二进制路径。服务会删除对应 IDA 数据库文件并重新分析，旧 IDB 中的人工修改会丢失。不能传 `.i64`、`.idb` 或数据库组件直接强制重建。

## 超时、取消与崩溃

| 情况 | native 行为 |
| --- | --- |
| 请求在执行前取消 | 跳过请求，worker 保留 |
| Python / 分析工具执行中取消或超时 | 终止目标 worker；其他数据库和服务保留 |
| worker 崩溃或协议损坏 | 标记断开并报告错误，不自动重试 |
| 再次打开失效目标 | 回收旧 worker，重新创建实例；使用新的 `instance_id` |

执行超时默认 360 秒，可用 `execute_python(timeout=...)` 调整。native 的开库和自动分析请求另有 360 秒上限。已经开始的 open、save、close 操作不支持相同的取消中断。未保存修改可能丢失，异常前的部分修改可能已执行。

Nexus 使用官方实现管理超时、取消、共享租约和恢复。实机验证中，9.4 无头 worker 异常退出后重新开库，恢复了已保存的 checkpoint；未保存的数据不保证恢复。native 没有 Nexus 的自动恢复机制。

## 空闲释放

```sh
.venv/bin/ida-mcp-server --backend nexus --idle-timeout 900
```

`--idle-timeout` 仅 Nexus 支持，单位为秒，必须是有限正数；`0` 关闭，默认关闭。也可设置 `IDA_MCP_IDLE_TIMEOUT`，命令行优先。

计时针对本会话的无头数据库租约，数据库请求会刷新计时。到期后本会话的实例 ID 失效；其他客户端的租约和 GUI 保留。最后一个租约释放时，官方 worker 保存并关闭 IDB。若收到到期通知后立即重新开库，服务会为该已知过渡最多等待 30 秒。

生命周期写入已启用的 JSONL。断连警告包含实例、原因和数据库状态，通过 MCP logging 发送；未保存修改仍不保证在异常退出时恢复。
