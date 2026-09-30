"""List functions and decompile one: python examples/basic_usage.py /path/to/binary."""

import argparse
import json

from ida_mcp_stdio import IDAMCPClient


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    args = parser.parse_args()
    with IDAMCPClient(args.binary) as client:
        client.initialize()
        rows = client.list_funcs(count=5)
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        if rows["data"]:
            print(
                json.dumps(
                    client.decompile(rows["data"][0]["addr"]),
                    ensure_ascii=False,
                    indent=2,
                )
            )


if __name__ == "__main__":
    main()
