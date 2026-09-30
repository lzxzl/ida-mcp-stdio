"""Analyze and close each input: python examples/batch_analysis.py /path/to/a /path/to/b."""

import argparse
import json

from ida_mcp_stdio import IDAMCPClient


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", nargs="+")
    args = parser.parse_args()
    with IDAMCPClient(tool_profile="compact") as client:
        client.initialize()
        for path in args.binaries:
            target = client.open_database(path)
            try:
                report = client.execute_python(
                    "tools.list_funcs(count=5)", instance_id=target["instance_id"]
                )
                print(
                    json.dumps({"path": target["path"], **report}, ensure_ascii=False)
                )
            finally:
                client.close_database(target["instance_id"])


if __name__ == "__main__":
    main()
