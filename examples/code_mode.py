"""Analyze related binaries with composable code and separate persistent globals.

Usage: python examples/code_mode.py /path/to/a.so /path/to/b.so
"""

from __future__ import annotations

import json
import sys

from ida_mcp_stdio import IDAMCPClient


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    with IDAMCPClient(tool_profile="compact") as client:
        client.initialize()
        print(json.dumps(client.reference("list_funcs"), ensure_ascii=False, indent=2))
        targets = [client.open_database(path) for path in sys.argv[1:]]
        for target in targets:
            report = client.execute_python(
                "functions = tools.list_funcs(count=20)\n"
                "{'total': functions['total'], 'sample': functions['data'][:5]}",
                instance_id=target["instance_id"],
            )
            print(
                json.dumps(
                    {"path": target["path"], **report}, ensure_ascii=False, indent=2
                )
            )
        for target in targets:
            client.close_database(target["instance_id"])


if __name__ == "__main__":
    main()
