"""Read functions by page: python examples/pagination_example.py /path/to/binary."""

import argparse
import json

from ida_mcp_stdio import IDAMCPClient


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--page-size", type=int, default=100)
    args = parser.parse_args()
    if args.page_size < 1:
        parser.error("--page-size must be positive")
    with IDAMCPClient(args.binary) as client:
        client.initialize()
        offset = 0
        while True:
            page = client.list_funcs(offset=offset, count=args.page_size)
            print(json.dumps(page, ensure_ascii=False))
            if not page["more"]:
                break
            offset += len(page["data"])


if __name__ == "__main__":
    main()
