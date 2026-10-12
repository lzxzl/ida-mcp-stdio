"""Auxiliary commands that do not initialize IDA."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

COMMANDS = {
    "stdio",
    "http",
    "dashboard",
    "logs",
    "hook",
    "install",
    "update",
    "benchmark",
}


def state_directory() -> Path:
    configured = os.environ.get("IDA_MCP_STDIO_STATE_DIR")
    if configured:
        path = Path(configured).expanduser()
        if not path.is_absolute():
            raise ValueError("state directory must be an absolute path")
        return path
    return Path.home() / ".local" / "state" / "ida-mcp-stdio"


def run_command(command: str, argv: list[str]) -> int | None:
    if command in {"stdio", "http"}:
        from .server import main

        return main((["--transport", "http"] if command == "http" else []) + argv)
    if command == "install":
        from .install import main

        return main(argv)
    if command == "update":
        from .install import update_main

        return update_main(argv)
    if command == "hook":
        from .hooks import cli

        return cli(argv)
    if command == "benchmark":
        from .benchmark import main

        return main(argv)
    parser = argparse.ArgumentParser(prog="ida-mcp-server " + command)
    parser.add_argument("--state-dir", type=Path, default=state_directory())
    if command == "dashboard":
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=8740)
        parser.add_argument(
            "--open", action="store_true", help="Open the local dashboard in a browser"
        )
        parser.add_argument("--session", type=Path, help="Session JSONL to export")
        parser.add_argument(
            "--export",
            type=Path,
            help="Write a standalone HTML view (requires --session)",
        )
        args = parser.parse_args(argv)
        from .dashboard import export_dashboard, serve_dashboard

        if args.export:
            if not args.session:
                parser.error("--export requires --session")
            print(
                export_dashboard(
                    args.session.expanduser(), args.export.expanduser()
                ).resolve()
            )
        else:
            if args.session:
                parser.error("--session is used with --export")
            serve_dashboard(
                args.state_dir.expanduser(), args.host, args.port, args.open
            )
    elif command == "logs":
        parser.add_argument(
            "--output", type=Path, required=True, help="Destination ZIP archive"
        )
        parser.add_argument(
            "--session",
            type=Path,
            action="append",
            help="Limit export to these session JSONL files",
        )
        parser.add_argument("--no-transcripts", action="store_true")
        args = parser.parse_args(argv)
        from .logs import export_logs

        print(
            export_logs(
                args.state_dir.expanduser(),
                args.output.expanduser(),
                args.session,
                not args.no_transcripts,
            ).resolve()
        )
    else:
        parser.error("Unknown command")
    return 0
