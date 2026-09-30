# 数据库管理

## 工具参数

| 工具 | 参数 | 行为 |
| --- | --- | --- |
| `open_database` | `path` 或兼容参数 `binary_path`；`set_current=true`；`force_reanalyze=false` | 打开二进制或 IDB，返回 `instance_id` |
| `list_databases` | 无 | native 返回自身持有实例；Nexus 还返回本机可发现实例 |
| `save_database` | `instance_id` 可选 | 保存指定或当前 IDB |
| `close_database` | `instance_id` 可选；`save=true` | native 保存并关闭 worker；Nexus 保存并释放租约 |

打开新库会保留已有库。native 的 `set_current=false` 不改变当前目标；Nexus 没有当前目标时仍会自动选中新开的库，已有当前目标时保持原选择。`execute_python(instance_id=...)` 可访问任一持有实例。旧分析工具直接调用时使用当前数据库。

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

native 规范化路径后复用同一服务内的活跃目标。默认最多四个活跃 worker，`--max-workers` 可调整。容量满时拒绝新库，需要主动关闭已有目标。

Nexus 列表中 `available` / `unavailable` 条目可能尚未被当前会话持有，`instance_id` 为 null。先用其 `path` 调用 `open_database`，取得会话实例 ID 后再执行或关闭。`current` / `attached` 表示已有租约。

## 保存与重建

正常关闭和服务 EOF 会尝试保存、回收数据库。重要修改后应主动 `save_database`，减少异常退出造成的损失。

native 可用 `close_database(save=False)` 跳过本次关闭保存。它不会撤销其他文件写入，也不是只读模式。Nexus 共享 IDB，拒绝 `save=False`。

`force_reanalyze=true` 仅 native 支持：先关闭该活跃目标，再传入原始二进制路径。服务会删除对应 IDA 数据库文件并重新分析，旧 IDB 中的人工修改会丢失。不能传 `.i64`、`.idb` 或数据库组件直接强制重建。

## 超时、取消与崩溃

| 情况 | native 行为 |
| --- | --- |
| 请求在执行前取消 | 跳过请求，worker 保留 |
| Python / 分析工具执行中取消或超时 | 终止目标 worker；其他数据库和服务保留 |
| worker 崩溃或协议损坏 | 标记断开并报告错误，不自动重试 |
| 再次打开失效目标 | 回收旧 worker，重新创建实例；使用新的 `instance_id` |

执行超时默认 360 秒，可用 `execute_python(timeout=...)` 调整。native 开库 / 自动分析请求也有独立的 360 秒上限。已开始的 open / save / close 不提供相同的取消中断。未保存修改可能丢失，异常前的部分修改可能已执行。

Nexus 的超时、取消、共享租约和恢复策略由官方实现管理。已验证 9.4 无头 worker 异常退出后重新开库恢复已保存的 checkpoint；未保存数据不保证恢复。不能把 Nexus 的恢复能力当作 native 自动恢复。
