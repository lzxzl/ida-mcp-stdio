"""PreToolUse adapters that correlate MCP traces with agent transcripts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

_IDA_TOOL = re.compile(r"^mcp__(?:.*[_:])?ida[-_]mcp[-_]stdio__.+$")
_ZCODE_EVENTS = {
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
}


def _no_symlinks(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            # macOS exposes these standard system directories through aliases.
            if (
                sys.platform == "darwin"
                and str(candidate) in {"/tmp", "/var"}
                and str(candidate.resolve()) == "/private" + str(candidate)
            ):
                continue
            raise ValueError(f"Refusing symlinked transcript path: {candidate}")


def _strict_json(text: str) -> dict:
    def constant(value):
        raise ValueError(f"Invalid JSON number: {value}")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(text, parse_constant=constant, object_pairs_hook=unique)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON transcript record: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError("Transcript record must be a JSON object")
    # Reject overflow such as 1e999 as well as explicit NaN/Infinity.
    json.dumps(value, allow_nan=False)
    return value


@contextmanager
def _snapshot_lock(target: Path):
    root = target.parent
    _no_symlinks(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        root.chmod(0o700)
    lock = target.with_suffix(".lock")
    _no_symlinks(lock)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(lock, flags, 0o600), "r+b") as handle:
        if os.name == "nt":
            import msvcrt

            if not handle.read(1):
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            os.fchmod(handle.fileno(), 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _append_snapshot(target: Path, header: dict, record: dict) -> Path:
    with _snapshot_lock(target):
        _no_symlinks(target)
        original = target.read_text(encoding="utf-8") if target.exists() else ""
        records = [_strict_json(line) for line in original.splitlines() if line.strip()]
        if target.exists() and (
            not records
            or records[0] != header
            or any(r.get("session_id") != header["session_id"] for r in records)
        ):
            raise ValueError("Unmanaged or mismatched session snapshot")
        encoded = json.dumps(
            record, ensure_ascii=False, sort_keys=True, allow_nan=False
        )
        record["snapshot_id"] = hashlib.sha256(encoded.encode()).hexdigest()
        # Equal prompts in separate turns are separate recorded events.
        record["timestamp"] = datetime.now(timezone.utc).isoformat()
        content = (
            (original if records else json.dumps(header) + "\n")
            + json.dumps(record, ensure_ascii=False, allow_nan=False)
            + "\n"
        )
        descriptor, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=target.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                if os.name != "nt":
                    os.fchmod(handle.fileno(), 0o600)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            _no_symlinks(target)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return target


def _zcode_snapshot(payload: dict, state_dir: Path | None) -> Path:
    session_id = payload.get("session_id", payload.get("sessionId"))
    if not isinstance(session_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}", session_id
    ):
        raise ValueError("ZCode session_id must be a single safe path component")
    event = payload.get("hook_event_name", payload.get("hookEventName"))
    if event not in _ZCODE_EVENTS:
        raise ValueError("Unsupported ZCode hook event")
    source_name = payload.get("transcript_path", payload.get("transcriptPath"))
    if not isinstance(source_name, str) or not source_name or "\x00" in source_name:
        raise ValueError("ZCode transcript_path must be a path")
    source = Path(source_name).expanduser()
    if not source.is_absolute():
        raise ValueError("ZCode transcript_path must be absolute")
    _no_symlinks(source)
    if not source.is_file():
        raise ValueError("ZCode transcript_path must identify a regular file")
    if source.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("ZCode transcript exceeds the snapshot limit")
    transcript = [
        _strict_json(line)
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for record in transcript:
        for key in ("session_id", "sessionId", "sessionID"):
            if key in record and record[key] != session_id:
                raise ValueError("Transcript record belongs to another session")
    if state_dir is None:
        from .cli import state_directory

        state_dir = state_directory() / "transcripts" / "zcode"
    root = Path(os.path.abspath(Path(state_dir).expanduser()))
    target = root / (hashlib.sha256(session_id.encode()).hexdigest() + ".jsonl")
    _no_symlinks(target)
    header = {"type": "ida_mcp_hook_session", "format": 1, "session_id": session_id}
    record = {
        "type": "ida_mcp_hook",
        "session_id": session_id,
        "hook_event_name": event,
        "transcript": transcript,
    }
    for snake, camel in (
        ("tool_name", "toolName"),
        ("tool_input", "toolInput"),
        ("tool_use_id", "toolCallId"),
        ("tool_response", "toolResponse"),
        ("error", "error"),
        ("prompt", "prompt"),
        ("last_assistant_message", "responseText"),
    ):
        value = payload.get(snake, payload.get(camel))
        if value is not None:
            record[snake] = value
    return _append_snapshot(target, header, record)


def hook_response(
    platform: str, payload: dict, *, state_dir: Path | None = None
) -> dict:
    """Return a hook response without mutating the supplied tool arguments."""
    platform = "claude" if platform == "claude-code" else platform
    if platform not in {"claude", "codex", "copilot", "zcode"}:
        raise ValueError(f"unsupported platform: {platform}")
    if not isinstance(payload, dict):
        raise ValueError("input must be a JSON object")
    if platform == "zcode":
        for snake, camel in (
            ("session_id", "sessionId"),
            ("transcript_path", "transcriptPath"),
            ("hook_event_name", "hookEventName"),
        ):
            if (
                snake in payload
                and camel in payload
                and payload[snake] != payload[camel]
            ):
                raise ValueError(f"Conflicting ZCode {snake} aliases")
        tool = payload.get("tool_name", payload.get("toolName", ""))
        event = payload.get("hook_event_name", payload.get("hookEventName"))
        if event in {"PreToolUse", "PostToolUse", "PostToolUseFailure"} and (
            not isinstance(tool, str) or not _IDA_TOOL.fullmatch(tool)
        ):
            return {}
        if event == "PreToolUse":
            arguments = payload.get("tool_input", payload.get("toolInput"))
            if not isinstance(arguments, dict):
                raise ValueError("ZCode tool_input must be an object")
            if "_meta" in arguments and not isinstance(arguments["_meta"], dict):
                raise ValueError("ZCode tool_input._meta must be an object")
        path = str(_zcode_snapshot(payload, state_dir))
        if event != "PreToolUse":
            return {}
    else:
        path = payload.get("transcript_path")
    arguments = payload.get("toolArgs" if platform == "copilot" else "tool_input")
    if platform == "zcode" and not isinstance(arguments, dict):
        arguments = payload.get("toolInput")
    if not isinstance(arguments, dict):
        arguments = payload.get("input")
    updated = dict(arguments) if isinstance(arguments, dict) else {}
    existing = updated.pop("_meta", {})
    metadata = dict(existing) if isinstance(existing, dict) else {}
    key = f"{platform}_session_path"
    metadata.pop(key, None)
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
    state_dir: str | Path | None = None,
) -> dict | int:
    """With payload return a dict; otherwise read JSON stdin and return CLI status.

    CLI status 1 indicates invalid input; 2 indicates an unsupported platform.
    Diagnostics go to stderr, keeping stdout exclusively machine-readable JSON.
    """
    if payload is not None:
        return hook_response(platform, payload, state_dir=state_dir)
    source = stdin if stdin is not None else sys.stdin
    output = stdout if stdout is not None else sys.stdout
    errors = stderr if stderr is not None else sys.stderr
    platform = "claude" if platform == "claude-code" else platform
    if platform not in {"claude", "codex", "copilot", "zcode"}:
        print(f"ida-mcp hook: unsupported platform: {platform}", file=errors)
        return 2
    try:
        response = hook_response(
            platform, _strict_json(source.read()), state_dir=state_dir
        )
        encoded = json.dumps(response, ensure_ascii=False, allow_nan=False)
    except (OSError, ValueError, TypeError) as exc:
        print(f"ida-mcp hook: {exc}", file=errors)
        return 1
    print(encoded, file=output)
    return 0


def cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ida-mcp-server hook",
        description="Attach an agent transcript to MCP calls.",
    )
    parser.add_argument(
        "platform", choices=["claude", "claude-code", "codex", "copilot", "zcode"]
    )
    parser.add_argument(
        "--state-dir", type=Path, help="Private transcript snapshot directory (ZCode)"
    )
    args = parser.parse_args(argv)
    return run_hook(args.platform, state_dir=args.state_dir)


if __name__ == "__main__":
    raise SystemExit(cli())
