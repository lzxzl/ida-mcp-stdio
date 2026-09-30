"""Record an MCP session: python examples/trace_logging_example.py /path/to/binary."""

import argparse
import json
from pathlib import Path

from ida_mcp_stdio import IDAMCPClient


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--log", default="logs/session.jsonl")
    args = parser.parse_args()
    log_path = Path(args.log).expanduser().resolve()
    with IDAMCPClient(
        args.binary,
        server_args=["--agent", "python-example", "--session-log", str(log_path)],
    ) as client:
        client.initialize()
        print(json.dumps(client.list_funcs(count=5), ensure_ascii=False, indent=2))
    print(f"Session log: {log_path}")


if __name__ == "__main__":
    main()
