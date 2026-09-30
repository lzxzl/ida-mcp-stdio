"""PreToolUse adapters that correlate MCP traces with agent transcripts."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO


def hook_response(platform: str, payload: dict) -> dict:
    """Return a hook response without mutating the supplied tool arguments."""
    platform = "claude" if platform == "claude-code" else platform
    if platform not in {"claude", "codex", "copilot"}:
        raise ValueError(f"unsupported platform: {platform}")
    if not isinstance(payload, dict):
        raise ValueError("input must be a JSON object")
    arguments = payload.get("toolArgs" if platform == "copilot" else "tool_input")
    if not isinstance(arguments, dict):
        arguments = payload.get("input")
    updated = dict(arguments) if isinstance(arguments, dict) else {}
    existing = updated.pop("_meta", {})
    metadata = dict(existing) if isinstance(existing, dict) else {}
    key = f"{platform}_session_path"
    metadata.pop(key, None)
    path = payload.get("transcript_path")
    if platform == "copilot":
        path = None
        session_id = payload.get("sessionId")
        if isinstance(session_id, str) and session_id:
            if (
                session_id in {".", ".."}
                or "/" in session_id
                or "\\" in session_id
                or "\x00" in session_id
            ):
                raise ValueError("sessionId must be a single path component")
            configured = os.environ.get("COPILOT_HOME")
            home = (
                Path(configured).expanduser()
                if configured
                else Path.home() / ".copilot"
            )
            path = str(home / "session-state" / session_id / "events.jsonl")
    if isinstance(path, str) and path.strip() and "\x00" not in path:
        metadata[key] = path
    if metadata:
        updated["_meta"] = metadata
    if platform == "copilot":
        return {"permissionDecision": "allow", "modifiedArgs": updated}
    output = {"hookEventName": "PreToolUse", "updatedInput": updated}
    if platform == "codex":
        output["permissionDecision"] = "allow"
    return {"hookSpecificOutput": output}


def run_hook(
    platform: str,
    payload: dict | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> dict | int:
    """With payload return a dict; otherwise read JSON stdin and return CLI status.

    CLI status 1 indicates invalid input; 2 indicates an unsupported platform.
    Diagnostics go to stderr, keeping stdout exclusively machine-readable JSON.
    """
    if payload is not None:
        return hook_response(platform, payload)
    source = stdin if stdin is not None else sys.stdin
    output = stdout if stdout is not None else sys.stdout
    errors = stderr if stderr is not None else sys.stderr
    platform = "claude" if platform == "claude-code" else platform
    if platform not in {"claude", "codex", "copilot"}:
        print(f"ida-mcp hook: unsupported platform: {platform}", file=errors)
        return 2
    try:
        response = hook_response(platform, json.load(source))
    except (ValueError, TypeError) as exc:
        print(f"ida-mcp hook: {exc}", file=errors)
        return 1
    print(json.dumps(response, ensure_ascii=False, allow_nan=False), file=output)
    return 0


def cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ida-mcp-server hook",
        description="Attach an agent transcript to MCP calls.",
    )
    parser.add_argument(
        "platform", choices=["claude", "claude-code", "codex", "copilot"]
    )
    return run_hook(parser.parse_args(argv).platform)


if __name__ == "__main__":
    raise SystemExit(cli())
