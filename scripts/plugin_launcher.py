"""Launch a configured installation without downloads or shell interpretation."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    arguments = sys.argv[1:]
    if not arguments or arguments[0] != "hook":
        backend = os.environ.get("IDA_MCP_STDIO_BACKEND")
        if backend:
            if backend not in {"native", "nexus"}:
                return fail("IDA_MCP_STDIO_BACKEND must be native or nexus.")
            if not any(
                value == "--backend" or value.startswith("--backend=")
                for value in arguments
            ):
                arguments = [*arguments, "--backend", backend]
    root = Path(__file__).resolve().parents[1]
    configured = os.environ.get("IDA_MCP_STDIO_PYTHON")
    if configured:
        python = Path(configured)
        if not python.is_absolute():
            return fail("IDA_MCP_STDIO_PYTHON must be an absolute executable path.")
    else:
        relative = Path("Scripts/python.exe" if os.name == "nt" else "bin/python")
        candidates = [
            Path(value) / "venv" / relative
            for key in ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA")
            if (value := os.environ.get(key)) and Path(value).is_absolute()
        ]
        candidates.append(root / ".venv" / relative)
        python = next((path for path in candidates if path.is_file()), None)
        if python is None:
            return fail("No configured Python installation was found.")

    # find_spec locates the top-level package without importing it or IDA.
    probe = (
        "import importlib.util, sys; "
        "sys.exit(0 if sys.version_info >= (3, 10) "
        "and importlib.util.find_spec('ida_mcp_stdio') is not None else 1)"
    )
    try:
        checked = subprocess.run(
            [str(python), "-c", probe],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if checked.returncode:
            return fail(f"{python} must provide Python 3.10+ and ida-mcp-stdio.")
        os.execv(str(python), [str(python), "-m", "ida_mcp_stdio", *arguments])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return fail(f"Cannot run configured Python {python}: {exc}")
    return 0


def fail(reason: str) -> int:
    print(
        "ida-mcp-stdio plugin: " + reason + "\n"
        "Create a private environment: python3 -m venv /absolute/private/venv\n"
        "Install this checkout: /absolute/private/venv/bin/python -m pip install /absolute/path/to/ida-mcp-stdio\n"
        "Set IDA_MCP_STDIO_PYTHON=/absolute/private/venv/bin/python in the client environment.\n"
        "Windows: use the environment's Scripts/python.exe.\n"
        "插件需要 Python 3.10+ 与已安装的 ida-mcp-stdio；请在私有环境安装本仓库，并将解释器绝对路径设置为 IDA_MCP_STDIO_PYTHON。",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
