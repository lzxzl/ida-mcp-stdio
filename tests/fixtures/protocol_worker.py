"""External protocol fixture: no IDA license or production test mode needed."""

import json
import sys

from ida_mcp_stdio.execution import execute_code

namespace = {}
path = None
for line in sys.stdin:
    request = json.loads(line)
    action = request["action"]
    if action == "open":
        path = request["path"]
        result = {"success": True, "path": path, "existing_db": False}
    elif action == "execute":
        result = execute_code(
            request["code"], namespace, request.get("persist_globals", True)
        )
    elif action == "save":
        result = {"saved": True, "idb_path": path + ".i64"}
    elif action == "close":
        result = {"success": "close-fail" not in path, "saved": request["save"]}
    else:
        result = {"path": path}
    print(json.dumps({"id": request["id"], "result": result}), flush=True)
    if action == "close" and result["success"]:
        break
