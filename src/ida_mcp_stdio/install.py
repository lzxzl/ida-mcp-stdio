"""Install client configurations and upgrade an explicitly selected environment.

This module deliberately uses the standard library only. It never imports IDA or
starts an MCP server, and dry runs report only the generated server settings.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .gui import GuiInstallError

SERVER_NAME = "ida-mcp-stdio"
CLIENTS = ("codex", "claude-code", "claude-desktop", "opencode", "zcode")
DEFAULT_SOURCE = "git+https://github.com/lzxzl/ida-mcp-stdio.git@main"
_REMOTE_FIELDS = {
    "url",
    "http_headers",
    "env_http_headers",
    "bearer_token_env_var",
    "headers",
    "oauth",
}
_DEFAULT_FIELDS = {
    "enabled",
    "startup_timeout_sec",
    "tool_timeout_sec",
    "timeout",
    "timeoutMs",
}
_ARGUMENT_NAMES = {
    "--backend": "backend",
    "--ida-dir": "ida_dir",
    "--tool-profile": "tool_profile",
    "--idle-timeout": "idle_timeout",
    "--agent": "agent",
    "--session-log": "session_log",
}
_HOOK_MATCHER = r"mcp__(.*[_:])?ida[-_]mcp[-_]stdio__.*"


@dataclass(frozen=True)
class InstallResult:
    client: str
    path: Path
    changed: bool
    server: dict
    backup: Path | None = None
    required_extras: tuple[str, ...] = ()
    hook_settings: dict | None = None


@dataclass(frozen=True)
class _Plan:
    result: InstallResult
    original: str | None
    updated: str


def _absolute(path: str | Path) -> Path:
    # Resolving symlinks would turn a venv interpreter into its global Python.
    return Path(os.path.abspath(Path(path).expanduser()))


def _read_text(path: Path) -> str:
    with path.open(encoding="utf-8", newline="") as handle:
        return handle.read()


def normalize_clients(clients: str | Iterable[str]) -> tuple[str, ...]:
    values = [clients] if isinstance(clients, str) else list(clients)
    selected = []
    for value in values:
        for client in value.split(","):
            client = client.strip().lower()
            candidates = CLIENTS if client == "all" else (client,)
            for candidate in candidates:
                if candidate not in CLIENTS:
                    raise ValueError(
                        f"Unknown client {candidate!r}; choose {', '.join(CLIENTS)} or all"
                    )
                if candidate not in selected:
                    selected.append(candidate)
    if not selected:
        raise ValueError("Select at least one client")
    return tuple(selected)


def client_config_path(
    client: str, *, home: Path | None = None, platform: str | None = None
) -> Path:
    home = _absolute(home or Path.home())
    platform = platform or sys.platform
    if client == "codex":
        return home / ".codex" / "config.toml"
    if client == "claude-code":
        return home / ".claude.json"
    if client == "claude-desktop":
        if platform == "darwin":
            return (
                home
                / "Library"
                / "Application Support"
                / "Claude"
                / "claude_desktop_config.json"
            )
        if platform == "win32":
            return (
                home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
            )
        return home / ".config" / "Claude" / "claude_desktop_config.json"
    if client == "opencode":
        directory = home / ".config" / "opencode"
        json_path = directory / "opencode.json"
        jsonc_path = directory / "opencode.jsonc"
        return (
            jsonc_path if jsonc_path.exists() and not json_path.exists() else json_path
        )
    if client == "zcode":
        return home / ".zcode" / "cli" / "config.json"
    raise ValueError(f"Unknown client {client!r}")


def _server_settings(
    client: str,
    *,
    python: Path,
    backend: str,
    ida_dir: str | Path | None,
    tool_profile: str,
    idle_timeout: float | None,
    agent: str | None,
    session_log: str | None,
) -> dict:
    if backend not in ("native", "nexus"):
        raise ValueError("Backend must be native or nexus")
    if tool_profile not in ("compact", "legacy", "full"):
        raise ValueError("Tool profile must be compact, legacy or full")
    if idle_timeout is not None:
        if not math.isfinite(idle_timeout) or idle_timeout < 0:
            raise ValueError("Idle timeout must be finite and nonnegative")
        if backend == "native" and idle_timeout > 0:
            raise ValueError("Positive idle timeout requires the nexus backend")
    args = [
        "-u",
        "-m",
        "ida_mcp_stdio",
        "--backend",
        backend,
        "--tool-profile",
        tool_profile,
        "--agent",
        agent or client,
    ]
    if ida_dir is not None:
        directory = _absolute(ida_dir)
        if (directory / "Contents" / "MacOS").is_dir():
            directory = directory / "Contents" / "MacOS"
        if not directory.is_dir():
            raise ValueError(f"IDA directory does not exist: {directory}")
        args.extend(["--ida-dir", str(directory)])
    if idle_timeout is not None:
        args.extend(["--idle-timeout", format(idle_timeout, "g")])
    if session_log is not None:
        args.extend(["--session-log", session_log])
    if client == "codex":
        return {
            "command": str(python),
            "args": args,
            "enabled": True,
            "startup_timeout_sec": 30,
            "tool_timeout_sec": 420,
        }
    if client == "opencode":
        return {
            "type": "local",
            "command": [str(python), *args],
            "enabled": True,
            "timeout": 420000,
        }
    settings = {"command": str(python), "args": args}
    if client in ("claude-code", "zcode"):
        settings["type"] = "stdio"
        settings["timeout" if client == "claude-code" else "timeoutMs"] = 420000
    return settings


def _unique_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _json_document(original: str, path: Path) -> dict:
    try:
        data = json.loads(original or "{}", object_pairs_hook=_unique_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {path}: {exc.msg} at line {exc.lineno}; JSONC comments and trailing commas require manual editing"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(f"Configuration must be an object: {path}")
    return data


def _json_server(data: dict, client: str) -> dict:
    keys = (
        ("mcp", "servers")
        if client == "zcode"
        else ("mcp",) if client == "opencode" else ("mcpServers",)
    )
    current = data
    for key in keys:
        if key not in current:
            current[key] = {}
        if not isinstance(current[key], dict):
            raise ValueError(f"{'.'.join(keys)} must be an object")
        current = current[key]
    if SERVER_NAME not in current:
        current[SERVER_NAME] = {}
    server = current[SERVER_NAME]
    if not isinstance(server, dict):
        raise ValueError(f"{SERVER_NAME} configuration must be an object")
    return server


def _json_update(
    original: str,
    path: Path,
    client: str,
    settings: dict,
    *,
    remove_remote: bool = True,
) -> str:
    data = _json_document(original, path)
    server = _json_server(data, client)
    _merge_server_fields(server, settings, remove_remote=remove_remote)
    # Avoid formatting-only changes and needless backups on repeat installation.
    if original and data == _json_document(original, path):
        return original
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _pieces(text: str, separator: str = "\n") -> list[tuple[int, int]]:
    """Locate delimiters outside TOML/JSON strings, comments and containers."""
    pieces = []
    start = 0
    i = 0
    quote = ""
    depth = []
    comment = False
    while i < len(text):
        char = text[i]
        if comment:
            if char == "\n":
                comment = False
                if not depth and separator == "\n":
                    pieces.append((start, i + 1))
                    start = i + 1
            i += 1
            continue
        if quote:
            if quote.startswith('"') and char == "\\":
                i += 2
                continue
            if text.startswith(quote, i):
                width = len(quote)
                if width == 3:
                    # TOML allows one or two literal quotes before the closing
                    # triple delimiter (four or five consecutive quote marks).
                    while width < 5 and text.startswith(quote[0], i + width):
                        width += 1
                i += width
                quote = ""
                continue
            if len(quote) == 1 and char == "\n":
                raise ValueError("Unterminated single-line string in TOML")
            i += 1
            continue
        if char in "\"'":
            quote = char * 3 if text.startswith(char * 3, i) else char
            i += len(quote)
            continue
        if char == "#":
            comment = True
        elif char in "[{":
            depth.append(char)
        elif char in "]}":
            if not depth or (depth.pop(), char) not in (("[", "]"), ("{", "}")):
                raise ValueError("Unbalanced containers in TOML")
        elif char == separator and not depth:
            pieces.append((start, i + 1 if separator == "\n" else i))
            start = i + 1
        i += 1
    if quote or depth:
        raise ValueError("Unterminated string or container in TOML")
    if start < len(text):
        pieces.append((start, len(text)))
    return pieces


def _without_comment(text: str) -> str:
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif quote:
            if quote == '"' and char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "#":
            return text[:index]
    return text


def _key_parts(text: str) -> tuple[str, ...]:
    parts = []
    pattern = re.compile(r"""\s*("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)\s*(\.|$)""")
    while text:
        match = pattern.match(text)
        if not match:
            raise ValueError(f"Unsupported or invalid TOML key: {text!r}")
        key = match[1]
        if key.startswith('"'):
            # TOML's eight-digit Unicode escape is absent from JSON.
            key = re.sub(r"\\U([0-9a-fA-F]{8})", lambda m: chr(int(m[1], 16)), key)
            key = json.loads(key)
        elif key.startswith("'"):
            key = key[1:-1]
        parts.append(key)
        text = text[match.end() :]
        if match[2] == "." and not text:
            raise ValueError("Incomplete dotted TOML key")
    return tuple(parts)


def _assignment(text: str) -> tuple[tuple[str, ...], str, str]:
    # Equal signs may occur in quoted keys; the splitter ignores them.
    pieces = _pieces(text, "=")
    if len(pieces) < 2:
        raise ValueError("Expected a TOML key/value assignment")
    boundary = pieces[0][1]
    key_text = text[:boundary].strip()
    return _key_parts(key_text), key_text, text[boundary + 1 :].strip()


def _toml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return json.dumps(value, ensure_ascii=True)


def _inline_merge(
    value: str, path: tuple[str, ...], settings: dict, *, remove_remote: bool = True
) -> str:
    value = _without_comment(value).strip()
    if not value.startswith("{") or not value.endswith("}"):
        raise ValueError(
            "MCP server tables defined by assignment must be inline TOML tables"
        )
    entries = []
    seen = set()
    for start, end in _pieces(value[1:-1], ","):
        raw = value[1:-1][start:end].strip()
        if not raw:
            continue
        key, spelling, item = _assignment(raw)
        if path and key == (path[0],):
            item = _inline_merge(item, path[1:], settings, remove_remote=remove_remote)
            seen.add(path[0])
        elif not path and len(key) == 1:
            if key[0] in _REMOTE_FIELDS and remove_remote:
                continue
            if key[0] in settings:
                if key[0] not in _DEFAULT_FIELDS:
                    item = _toml_value(settings[key[0]])
                seen.add(key[0])
        entries.append(f"{spelling} = {item}")
    if path and path[0] not in seen:
        entries.append(
            f"{json.dumps(path[0])} = {_inline_merge('{}', path[1:], settings, remove_remote=remove_remote)}"
        )
    elif not path:
        entries.extend(
            f"{key} = {_toml_value(item)}"
            for key, item in settings.items()
            if key not in seen
        )
    return "{ " + ", ".join(entries) + " }"


def _fallback_toml_value(value: str):
    value = "\n".join(_without_comment(line) for line in value.splitlines()).strip()
    if not value:
        raise ValueError("Missing TOML value")
    if value.startswith('"'):
        try:
            return json.loads(value)
        except ValueError as exc:
            raise ValueError(
                "Advanced TOML strings require Python 3.11+ or the optional tomli package"
            ) from exc
    if value.startswith("'"):
        if not re.fullmatch(r"'[^'\r\n\x00-\x08\x0b-\x1f\x7f]*'", value):
            raise ValueError(
                "Advanced TOML strings require Python 3.11+ or the optional tomli package"
            )
        return value[1:-1]
    if value in ("true", "false"):
        return value == "true"
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        return [
            _fallback_toml_value(inner[start:end]) for start, end in _pieces(inner, ",")
        ]
    if value.startswith("{") and value.endswith("}"):
        result = {}
        inner = value[1:-1].strip()
        for start, end in _pieces(inner, ","):
            keys, _, item = _assignment(inner[start:end])
            current = result
            for key in keys[:-1]:
                current = current.setdefault(key, {})
                if not isinstance(current, dict):
                    raise ValueError("Conflicting dotted TOML keys")
            if keys[-1] in current:
                raise ValueError("Duplicate TOML key")
            current[keys[-1]] = _fallback_toml_value(item)
        return result
    number = r"[-+]?(?:0|[1-9](?:_?[0-9])*)(?:\.[0-9](?:_?[0-9])*)?(?:[eE][-+]?[0-9](?:_?[0-9])*)?"
    integer = (
        r"(?:0x[0-9a-fA-F](?:_?[0-9a-fA-F])*|0o[0-7](?:_?[0-7])*|0b[01](?:_?[01])*)"
    )
    if re.fullmatch(f"(?:{number}|{integer}|[-+]?(?:inf|nan))", value):
        return value
    raise ValueError(
        "Invalid or advanced TOML value; use Python 3.11+ or install the optional tomli package"
    )


def _fallback_validate_toml(text: str) -> dict:
    """Fail closed on TOML outside a validated subset when no reader exists."""
    data = {}
    context = ()
    explicit_tables = set()
    dotted_tables = set()
    sealed = set()
    for start, end in _pieces(text):
        statement = text[start:end]
        significant = _without_comment(statement).strip()
        if not significant:
            continue
        if significant.startswith("["):
            if significant.startswith("[[") or not significant.endswith("]"):
                raise ValueError(
                    "Advanced TOML tables require Python 3.11+ or the optional tomli package"
                )
            context = _key_parts(significant[1:-1])
            if context in explicit_tables or context in dotted_tables:
                raise ValueError("Duplicate or conflicting TOML table")
            explicit_tables.add(context)
            keys = context
        else:
            relative, _, value = _assignment(statement)
            keys = context + relative
        current = data
        for index, key in enumerate(keys):
            prefix = keys[: index + 1]
            if prefix in sealed:
                raise ValueError("Conflicting inline TOML table")
            if not significant.startswith("[") and index == len(keys) - 1:
                if key in current:
                    raise ValueError("Duplicate TOML key")
                current[key] = _fallback_toml_value(value)
                if isinstance(current[key], dict):
                    sealed.add(prefix)
            else:
                current = current.setdefault(key, {})
                if not isinstance(current, dict):
                    raise ValueError("Conflicting TOML keys and tables")
                if not significant.startswith("[") and index >= len(context):
                    dotted_tables.add(prefix)
    return data


def _validate_toml(text: str) -> dict:
    try:
        import tomllib as reader
    except ImportError:
        try:
            import tomli as reader
        except ImportError:
            try:
                from pip._vendor import tomli as reader
            except ImportError:
                return _fallback_validate_toml(text)
    try:
        return reader.loads(text)
    except ValueError as exc:
        raise ValueError(f"Invalid TOML: {exc}") from exc


def _codex_update(original: str, settings: dict, *, remove_remote: bool = True) -> str:
    """Edit managed keys without serializing or dropping unrelated TOML."""
    _validate_toml(original)
    target = ("mcp_servers", SERVER_NAME)
    context = ()
    replacements = []
    found = set()
    table_end = None
    field_context = None
    field_end = None
    inline = False
    for start, end in _pieces(original):
        statement = original[start:end]
        significant = _without_comment(statement).strip()
        if not significant:
            continue
        if significant.startswith("["):
            if context == target and table_end is None:
                table_end = start
            if (
                field_context is not None
                and context == field_context
                and field_end is None
            ):
                field_end = start
            array_table = significant.startswith("[[")
            width = 2 if array_table else 1
            context = _key_parts(significant[width:-width])
            if context[:2] == target and array_table:
                raise ValueError(
                    "Codex MCP configuration must be a table, not an array of tables"
                )
            continue
        keys, spelling, value = _assignment(statement)
        full_key = context + keys
        if full_key == target or (full_key == target[:1] and context == ()):
            relative = target[len(full_key) :]
            merged = _inline_merge(
                value, relative, settings, remove_remote=remove_remote
            )
            replacements.append((start, end, f"{spelling} = {merged}\n"))
            inline = True
        elif full_key[:2] == target and len(full_key) == 3:
            field = full_key[-1]
            field_context = context
            if field in _REMOTE_FIELDS and remove_remote:
                replacements.append((start, end, ""))
            elif field in settings:
                found.add(field)
                if field not in _DEFAULT_FIELDS:
                    replacements.append(
                        (start, end, f"{spelling} = {_toml_value(settings[field])}\n")
                    )
    if not inline:
        missing = {key: value for key, value in settings.items() if key not in found}
        if table_end is not None or context == target:
            point = table_end if table_end is not None else len(original)
            addition = "".join(
                f"{key} = {_toml_value(value)}\n" for key, value in missing.items()
            )
        elif field_context is not None:
            point = field_end if field_end is not None else len(original)
            relative = target[len(field_context) :]
            prefix = ".".join(json.dumps(key) for key in relative)
            addition = "".join(
                f"{prefix + '.' if prefix else ''}{key} = {_toml_value(value)}\n"
                for key, value in missing.items()
            )
        else:
            point = len(original)
            addition = f"\n[mcp_servers.{SERVER_NAME}]\n" + "".join(
                f"{key} = {_toml_value(value)}\n" for key, value in missing.items()
            )
        if addition:
            if point and original[point - 1] != "\n":
                addition = "\n" + addition
            replacements.append((point, point, addition))
    updated = original
    for start, end, replacement in sorted(
        replacements, key=lambda item: (item[0], item[1]), reverse=True
    ):
        updated = updated[:start] + replacement + updated[end:]
    _validate_toml(updated)
    return updated


def _atomic_write(path: Path, content: str) -> None:
    _hook_path_safe(path, Path.home())
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            if os.name != "nt":
                os.fchmod(handle.fileno(), 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _hook_path_safe(path, Path.home())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _codex_hooks_supported() -> bool:
    executable = shutil.which("codex")
    if not executable or sys.platform == "win32":
        return False
    try:
        result = subprocess.run(
            [executable, "features", "list"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return any(
        re.fullmatch(r"hooks\s+stable\s+true", line.strip())
        for line in result.stdout.splitlines()
    )


def _hook_state_directory(home: Path, client: str) -> Path:
    if home == _absolute(Path.home()):
        from .cli import state_directory

        root = state_directory()
    else:
        root = home / ".local" / "state" / SERVER_NAME
    return root / "transcripts" / client


def _hook_path_safe(path: Path, home: Path, *, directory: bool = False) -> None:
    # Check ancestors as well as the leaf: a plugin directory can redirect writes.
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            if (
                sys.platform == "darwin"
                and str(candidate) in {"/tmp", "/var"}
                and str(candidate.resolve()) == "/private" + str(candidate)
            ):
                continue
            raise ValueError(f"Refusing symlinked configuration: {candidate}")
        if (
            (candidate != path or directory)
            and candidate.exists()
            and not candidate.is_dir()
        ):
            raise ValueError(f"Configuration parent must be a directory: {candidate}")


def _opencode_plugin_plan(home: Path) -> _Plan:
    path = home / ".config" / "opencode" / "plugins" / f"{SERVER_NAME}.js"
    _hook_path_safe(path, home)
    original = _read_text(path) if path.exists() else None
    marker = "// Managed by ida-mcp-stdio: active-session transcript plugin v1."
    if original is not None and not original.startswith(marker + "\n"):
        raise ValueError(f"Refusing to replace unmanaged OpenCode plugin: {path}")
    asset = _read_text(Path(__file__).parent / "assets" / "opencode-session.js")
    root = _hook_state_directory(home, "opencode")
    _hook_path_safe(root, home)
    updated = asset.replace(
        "__IDA_MCP_STATE_ROOT__", json.dumps(str(root), ensure_ascii=True)
    )
    return _Plan(
        InstallResult(
            "opencode-hooks",
            path,
            updated != original,
            {"plugin": str(path), "sdk_contract": "v1", "session_snapshots": str(root)},
        ),
        original,
        updated,
    )


def _hook_settings(client: str, python: Path, *, state_dir: Path | None = None) -> dict:
    arguments = ["-u", "-m", "ida_mcp_stdio", "hook", client]
    if client == "zcode":
        arguments += ["--state-dir", str(state_dir)]
        handler = {
            "type": "process",
            "command": str(python),
            "args": arguments,
            "timeoutMs": 10000,
        }
        events = {}
        for event in (
            "PreToolUse",
            "PostToolUse",
            "PostToolUseFailure",
            "UserPromptSubmit",
            "Stop",
        ):
            group = {"hooks": [dict(handler)]}
            if event in {"PreToolUse", "PostToolUse", "PostToolUseFailure"}:
                group["matcher"] = _HOOK_MATCHER
            events[event] = [group]
        return {"hooks": {"enabled": True, "events": events}}
    handler = {"type": "command", "timeout": 10}
    if client == "claude-code":
        # Official exec form is portable and never interpolates a shell string.
        handler.update(command=str(python), args=arguments)
    else:
        handler["command"] = shlex.join([str(python), *arguments])
    return {"hooks": {"PreToolUse": [{"matcher": _HOOK_MATCHER, "hooks": [handler]}]}}


def _hook_owned(handler: dict, client: str) -> bool:
    arguments = handler.get("args", [])
    if isinstance(arguments, list) and all(isinstance(arg, str) for arg in arguments):
        for index in range(len(arguments) - 2):
            if arguments[index : index + 3] == ["ida_mcp_stdio", "hook", client]:
                suffix = arguments[index + 3 :]
                if not suffix or (
                    client == "zcode"
                    and len(suffix) == 2
                    and suffix[0] == "--state-dir"
                ):
                    return True
    command = handler.get("command", "")
    return isinstance(command, str) and bool(
        re.search(rf"\bida_mcp_stdio\s+hook\s+{re.escape(client)}\s*$", command)
    )


def _hook_update(original: str, path: Path, client: str, settings: dict) -> str:
    data = _json_document(original, path)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"hooks must be an object: {path}")
    if client == "zcode":
        if "enabled" in hooks and not isinstance(hooks["enabled"], bool):
            raise ValueError(f"hooks.enabled must be a boolean: {path}")
        # An explicit disabled setting keeps unrelated dormant hooks disabled.
        hooks.setdefault("enabled", True)
        events = hooks.setdefault("events", {})
        if not isinstance(events, dict):
            raise ValueError(f"hooks.events must be an object: {path}")
        managed_events = settings["hooks"]["events"]
    else:
        events = hooks
        managed_events = {"PreToolUse": settings["hooks"]["PreToolUse"]}
    for event, managed_groups in managed_events.items():
        groups = events.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValueError(f"hooks {event} must be an array: {path}")
        managed_group = managed_groups[0]
        managed = managed_group["hooks"][0]
        installed = False
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                raise ValueError(
                    f"{event} matcher groups must contain a hooks array: {path}"
                )
            updated = []
            for handler in group["hooks"]:
                if not isinstance(handler, dict):
                    raise ValueError(f"{event} hook handlers must be objects: {path}")
                if group.get("matcher") == managed_group.get("matcher") and _hook_owned(
                    handler, client
                ):
                    if not installed:
                        updated.append({**handler, **managed})
                        installed = True
                else:
                    updated.append(handler)
            group["hooks"] = updated
        if not installed:
            groups.append(managed_group)
    if original and data == _json_document(original, path):
        return original
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _claude_update(
    original: str,
    path: Path,
    *,
    python: Path,
    options: dict,
    preserve_arguments: bool,
    explicit_overrides: dict,
) -> tuple[str, dict, tuple[str, ...]]:
    data = _json_document(original, path)
    root_server = _json_server(data, "claude-code")
    settings, extras = _configuration_settings(
        "claude-code",
        root_server,
        python=python,
        options=options,
        preserve_arguments=preserve_arguments,
        explicit_overrides=explicit_overrides,
    )
    _merge_server_fields(root_server, settings, remove_remote=not preserve_arguments)
    required = set(extras)
    projects = data.get("projects", {})
    if preserve_arguments and isinstance(projects, dict):
        for project in projects.values():
            servers = project.get("mcpServers", {}) if isinstance(project, dict) else {}
            if not isinstance(servers, dict) or SERVER_NAME not in servers:
                continue
            server = servers[SERVER_NAME]
            if not isinstance(server, dict):
                raise ValueError(
                    f"Project {SERVER_NAME} configuration must be an object: {path}"
                )
            updates, project_extras = _configuration_settings(
                "claude-code",
                server,
                python=python,
                options=options,
                preserve_arguments=True,
                explicit_overrides=explicit_overrides,
            )
            _merge_server_fields(server, updates, remove_remote=False)
            required.update(project_extras)
    updated = (
        original
        if original and data == _json_document(original, path)
        else json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    )
    return updated, settings, tuple(sorted(required))


def _claude_project_paths(original: str, *, home: Path) -> list[Path]:
    data = _json_document(original, home / ".claude.json")
    projects = data.get("projects", {})
    directories = []
    if isinstance(projects, dict):
        directories.extend(Path(name) for name in projects if Path(name).is_absolute())
    if home == _absolute(Path.home()):
        directories.append(Path.cwd())
    paths = set()
    for directory in directories:
        if not directory.is_dir():
            continue
        for relative in (
            ".mcp.json",
            ".claude/settings.local.json",
            ".claude/settings.json",
        ):
            path = _absolute(directory / relative)
            if path.is_file():
                paths.add(path)
    return sorted(paths)


def install_clients(
    clients: str | Iterable[str] = "all",
    *,
    home: str | Path | None = None,
    python: str | Path | None = None,
    platform: str | None = None,
    backend: str = "native",
    ida_dir: str | Path | None = None,
    tool_profile: str = "compact",
    idle_timeout: float | None = None,
    agent: str | None = None,
    session_log: str | None = "auto",
    dry_run: bool = False,
    backup_root: str | Path | None = None,
    client_settings: dict[str, dict] | None = None,
    hooks: bool = False,
    codex_hooks_supported: bool | None = None,
    preserve_arguments: bool = False,
    argument_overrides: dict | None = None,
) -> list[InstallResult]:
    """Merge server settings, back up originals, and atomically save each config.

    Every input is parsed before creating directories or modifying any file.
    ``server`` in each returned result contains generated settings only.
    """
    home = _absolute(home or Path.home())
    python = _absolute(python or sys.executable)
    backup_directory_root = (
        _absolute(backup_root)
        if backup_root
        else home / ".local" / "state" / SERVER_NAME / "backups"
    )
    _hook_path_safe(backup_directory_root, home, directory=True)
    plans = []
    selected_clients = normalize_clients(clients)
    for client in selected_clients:
        path = client_config_path(client, home=home, platform=platform)
        _hook_path_safe(path, home)
        original = _read_text(path) if path.exists() else None
        options = {
            "backend": backend,
            "ida_dir": ida_dir,
            "tool_profile": tool_profile,
            "idle_timeout": idle_timeout,
            "agent": agent,
            "session_log": session_log,
        }
        options.update((client_settings or {}).get(client, {}))
        existing_server = _existing_server(original or "", path, client)
        settings, extras = _configuration_settings(
            client,
            existing_server,
            python=python,
            options=options,
            preserve_arguments=preserve_arguments,
            explicit_overrides=argument_overrides or {},
        )
        if client == "codex":
            updated = _codex_update(
                original or "", settings, remove_remote=not preserve_arguments
            )
        elif client == "claude-code":
            updated, settings, extras = _claude_update(
                original or "",
                path,
                python=python,
                options=options,
                preserve_arguments=preserve_arguments,
                explicit_overrides=argument_overrides or {},
            )
        else:
            updated = _json_update(
                original or "",
                path,
                client,
                settings,
                remove_remote=not preserve_arguments,
            )
        plans.append(
            _Plan(
                InstallResult(
                    client, path, updated != original, settings, required_extras=extras
                ),
                original,
                updated,
            )
        )
        if client == "claude-code" and preserve_arguments:
            for project_path in _claude_project_paths(original or "", home=home):
                _hook_path_safe(project_path, home)
                project_original = _read_text(project_path)
                # An unrelated project file is outside the mutation scope.
                if SERVER_NAME not in project_original:
                    continue
                data = _json_document(project_original, project_path)
                servers = data.get("mcpServers", {})
                if not isinstance(servers, dict) or SERVER_NAME not in servers:
                    continue
                project_server = servers[SERVER_NAME]
                if not isinstance(project_server, dict):
                    raise ValueError(
                        f"Project {SERVER_NAME} configuration must be an object: {project_path}"
                    )
                project_settings, project_extras = _configuration_settings(
                    "claude-code",
                    project_server,
                    python=python,
                    options=options,
                    preserve_arguments=True,
                    explicit_overrides=argument_overrides or {},
                )
                project_updated = _json_update(
                    project_original,
                    project_path,
                    "claude-code",
                    project_settings,
                    remove_remote=False,
                )
                label = f"claude-code-project-{uuid.uuid5(uuid.NAMESPACE_URL, str(project_path)).hex[:12]}"
                plans.append(
                    _Plan(
                        InstallResult(
                            label,
                            project_path,
                            project_updated != project_original,
                            project_settings,
                            required_extras=project_extras,
                        ),
                        project_original,
                        project_updated,
                    )
                )
    if hooks:
        supported = (
            codex_hooks_supported
            if codex_hooks_supported is not None
            else _codex_hooks_supported() if "codex" in selected_clients else False
        )
        for client in selected_clients:
            if client == "opencode":
                plans.append(_opencode_plugin_plan(home))
                continue
            if client not in {"claude-code", "zcode"} and not (
                client == "codex" and supported
            ):
                continue
            path = (
                home / ".claude" / "settings.json"
                if client == "claude-code"
                else (
                    client_config_path("zcode", home=home)
                    if client == "zcode"
                    else home / ".codex" / "hooks.json"
                )
            )
            _hook_path_safe(path, home)
            original = _read_text(path) if path.exists() else None
            state_dir = (
                _hook_state_directory(home, client) if client == "zcode" else None
            )
            if state_dir is not None:
                _hook_path_safe(state_dir, home)
            settings = _hook_settings(client, python, state_dir=state_dir)
            prior_index = next(
                (
                    index
                    for index, plan in enumerate(plans)
                    if plan.result.path.resolve() == path.resolve()
                ),
                None,
            )
            if prior_index is not None:
                prior = plans[prior_index]
                if original != prior.original:
                    raise ValueError(f"Configuration changed during planning: {path}")
                updated = _hook_update(prior.updated, path, client, settings)
                plans[prior_index] = _Plan(
                    InstallResult(
                        prior.result.client,
                        prior.result.path,
                        updated != prior.original,
                        prior.result.server,
                        required_extras=prior.result.required_extras,
                        hook_settings=settings,
                    ),
                    prior.original,
                    updated,
                )
            else:
                updated = _hook_update(original or "", path, client, settings)
                plans.append(
                    _Plan(
                        InstallResult(
                            f"{client}-hooks", path, updated != original, settings
                        ),
                        original,
                        updated,
                    )
                )
    if dry_run:
        return [plan.result for plan in plans]
    changed = [plan for plan in plans if plan.result.changed]
    if not changed:
        return [plan.result for plan in plans]
    # Verify that no input changed during planning, before making any backups.
    for plan in changed:
        _hook_path_safe(plan.result.path, home)
        current = _read_text(plan.result.path) if plan.result.path.exists() else None
        if current != plan.original or plan.result.path.is_symlink():
            raise ValueError(
                f"Configuration changed during installation: {plan.result.path}"
            )
    backup_directory = None
    backups = {}
    if any(plan.original is not None for plan in changed):
        root = backup_directory_root
        _hook_path_safe(root, home, directory=True)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            root.chmod(0o700)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        backup_directory = root / f"{stamp}-{uuid.uuid4().hex[:8]}"
        backup_directory.mkdir(mode=0o700)
        # Complete every backup before replacing the first configuration.
        for plan in changed:
            if plan.original is not None:
                backup = (
                    backup_directory / f"{plan.result.client}-{plan.result.path.name}"
                )
                _atomic_write(backup, plan.original)
                backups[plan.result.client] = backup
    saved = []
    try:
        for plan in changed:
            _hook_path_safe(plan.result.path, home)
            _atomic_write(plan.result.path, plan.updated)
            saved.append(plan)
    except (OSError, ValueError):
        for plan in reversed(saved):
            if plan.original is None:
                plan.result.path.unlink()
            else:
                _atomic_write(plan.result.path, plan.original)
        raise
    return [
        InstallResult(
            plan.result.client,
            plan.result.path,
            plan.result.changed,
            plan.result.server,
            backups.get(plan.result.client),
            plan.result.required_extras,
            plan.result.hook_settings,
        )
        for plan in plans
    ]


def _inline_lookup(value: str, path: tuple[str, ...]) -> str | None:
    value = _without_comment(value).strip()
    if not value.startswith("{") or not value.endswith("}"):
        raise ValueError("Expected an inline TOML table")
    for start, end in _pieces(value[1:-1], ","):
        raw = value[1:-1][start:end].strip()
        if not raw:
            continue
        key, _, item = _assignment(raw)
        if key == path:
            return item
        if path[: len(key)] == key:
            return _inline_lookup(item, path[len(key) :])
    return None


def _codex_arguments(text: str) -> list[str]:
    return (
        _client_arguments(_existing_server(text, Path("config.toml"), "codex"), "codex")
        or []
    )


def _existing_server(text: str, path: Path, client: str) -> dict:
    if client != "codex":
        return _json_server(_json_document(text, path), client)
    document = _validate_toml(text)
    servers = document.get("mcp_servers", {})
    if not isinstance(servers, dict):
        raise ValueError("mcp_servers must be a TOML table")
    server = servers.get(SERVER_NAME, {})
    if not isinstance(server, dict):
        raise ValueError(f"{SERVER_NAME} must be a TOML table")
    return server


def _client_arguments(server: dict, client: str) -> list[str] | None:
    if client == "opencode":
        command = server.get("command")
        arguments = command[1:] if isinstance(command, list) else None
    else:
        arguments = server.get("args")
    if arguments is not None and (
        not isinstance(arguments, list)
        or not all(isinstance(arg, str) for arg in arguments)
    ):
        raise ValueError(f"Existing {client} server args must be an array of strings")
    return arguments


def _argument_start(arguments: list[str]) -> int:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "-m":
            return (
                index + 2
                if arguments[index : index + 2] == ["-m", "ida_mcp_stdio"]
                else 0
            )
        if argument in ("-W", "-X", "--check-hash-based-pycs"):
            index += 2
        elif argument in ("-", "--") or argument.startswith("-c"):
            return 0
        elif argument.startswith("-"):
            index += 1
        else:
            # A script or wrapper prefix is not a Python module invocation.
            return 0
    return 0


def _argument_options(arguments: list[str]) -> dict:
    options = {}
    index = _argument_start(arguments)
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            break
        name, separator, embedded = argument.partition("=")
        if name not in _ARGUMENT_NAMES:
            index += 1
            continue
        value = (
            embedded
            if separator
            else arguments[index + 1] if index + 1 < len(arguments) else None
        )
        consumes_value = not separator
        if name == "--session-log" and (value is None or value.startswith("--")):
            value, consumes_value = "auto", False
        if value is None or (value.startswith("--") and name != "--session-log"):
            raise ValueError(f"Missing value for existing {name}")
        options[_ARGUMENT_NAMES[name]] = (
            float(value) if name == "--idle-timeout" else value
        )
        index += 2 if consumes_value else 1
    return options


def _merge_arguments(arguments: list[str], overrides: dict[str, str]) -> list[str]:
    start = _argument_start(arguments)
    merged = arguments[:start]
    seen = set()
    index = start
    while index < len(arguments) and arguments[index] != "--":
        argument = arguments[index]
        name, separator, _ = argument.partition("=")
        if name not in overrides:
            merged.append(argument)
            index += 1
            continue
        if name not in seen:
            merged.extend([name, overrides[name]])
            seen.add(name)
        index += 1
        if (
            not separator
            and index < len(arguments)
            and not arguments[index].startswith("--")
        ):
            index += 1
    for name, value in overrides.items():
        if name not in seen:
            merged.extend([name, value])
    return merged + arguments[index:]


def _merge_server_fields(server: dict, settings: dict, *, remove_remote: bool) -> None:
    if remove_remote:
        for field in _REMOTE_FIELDS:
            server.pop(field, None)
    for field, value in settings.items():
        if field in _DEFAULT_FIELDS:
            server.setdefault(field, value)
        else:
            server[field] = value


def _configuration_settings(
    client: str,
    server: dict,
    *,
    python: Path,
    options: dict,
    preserve_arguments: bool,
    explicit_overrides: dict,
) -> tuple[dict, tuple[str, ...]]:
    existing = _client_arguments(server, client)
    if preserve_arguments and server.get("command") and "url" not in server:
        command = (
            server["command"][0]
            if client == "opencode" and isinstance(server["command"], list)
            else server["command"]
        )
        if not isinstance(command, str):
            raise ValueError(f"Existing {client} command must be an executable path")
        executable = re.split(r"[/\\]", command)[-1].lower()
        if executable in ("ida-mcp-server", "ida-mcp-server.exe", "ida-mcp-server.cmd"):
            existing = ["-u", "-m", "ida_mcp_stdio", *(existing or [])]
        elif existing is None or _argument_start(existing) == 0:
            raise ValueError(
                f"Cannot refresh unsupported {client} launcher; use install to configure a Python module or ida-mcp-server command"
            )
    effective = dict(options)
    if preserve_arguments and existing is not None:
        effective.update(_argument_options(existing))
        effective.update(explicit_overrides)
    # Unchanged IDA paths are retained even when that installation is currently offline.
    validation = dict(effective)
    if preserve_arguments and "ida_dir" not in explicit_overrides:
        validation["ida_dir"] = None
    settings = _server_settings(client, python=python, **validation)
    if preserve_arguments and "url" in server and not server.get("command"):
        if explicit_overrides:
            raise ValueError(
                f"Cannot apply startup flags to remote {client} configuration; use install to switch to stdio"
            )
        settings = {
            key: value for key, value in settings.items() if key in _DEFAULT_FIELDS
        }
    elif preserve_arguments and existing is not None:
        generated = (
            settings["command"][1:] if client == "opencode" else settings["args"]
        )
        values = _argument_options(generated)
        overrides = {
            flag: (
                format(values[name], "g")
                if name == "idle_timeout"
                else str(values[name])
            )
            for flag, name in _ARGUMENT_NAMES.items()
            if name in explicit_overrides
        }
        arguments = _merge_arguments(existing, overrides)
        if client == "opencode":
            settings["command"] = [str(python), *arguments]
        else:
            settings["args"] = arguments
        if "type" in server:
            settings["type"] = server["type"]
    for field in _DEFAULT_FIELDS:
        if field in settings and field in server:
            settings[field] = server[field]
    arguments = (
        settings.get("command", [])[1:]
        if client == "opencode" and isinstance(settings.get("command"), list)
        else settings.get("args", [])
    )
    effective_options = _argument_options(arguments)
    extras = []
    if effective_options.get("backend", "native") == "nexus":
        extras.append("nexus")
    body = arguments[_argument_start(arguments) :]
    if "--" in body:
        body = body[: body.index("--")]
    if body[:1] == ["http"] or any(
        body[index : index + 2] == ["--transport", "http"]
        or body[index] == "--transport=http"
        for index in range(len(body))
    ):
        extras.append("http")
    return settings, tuple(extras)


def _existing_options(client: str, *, home: Path, platform: str | None = None) -> dict:
    path = client_config_path(client, home=home, platform=platform)
    if not path.exists():
        return {}
    server = _existing_server(_read_text(path), path, client)
    return _argument_options(_client_arguments(server, client) or [])


def environment_python(environment: str | Path, *, platform: str | None = None) -> Path:
    directory = _absolute(environment)
    return (
        directory
        / ("Scripts" if (platform or sys.platform) == "win32" else "bin")
        / ("python.exe" if (platform or sys.platform) == "win32" else "python")
    )


def _virtual_environment(python: Path) -> Path:
    directory = python.parent.parent
    if (
        python.parent.name not in ("bin", "Scripts")
        or not (directory / "pyvenv.cfg").is_file()
    ):
        raise ValueError(
            f"Package upgrade requires a virtual environment interpreter: {python}; use --venv to create one"
        )
    if not python.is_file():
        raise ValueError(f"Virtual environment interpreter does not exist: {python}")
    return directory


def _package_source(source: str, backend: str) -> str:
    source = source.strip()
    if not source or source.startswith("-"):
        raise ValueError(
            "Package source must be a requirement, local path or URL, not a pip option"
        )
    if backend == "native":
        return source
    if backend != "nexus":
        raise ValueError("Backend must be native or nexus")
    return _with_extra(source, "nexus")


def _with_extra(source: str, extra: str) -> str:
    if source.startswith(("git+", "https://", "http://", "file://")):
        return f"{SERVER_NAME}[{extra}] @ {source}"
    if " @ " in source:
        package, url = source.split(" @ ", 1)
        return f"{_with_extra(package, extra)} @ {url}"
    trailing = re.fullmatch(r"(.*)\[([^][]*)\]", source)
    path = trailing[1] if trailing else source
    if (
        Path(path).exists()
        or path.startswith(("/", "./", "../", "~"))
        or re.match(r"^[A-Za-z]:[/\\]", path)
    ):
        extras = (
            [part.strip() for part in trailing[2].split(",") if part.strip()]
            if trailing
            else []
        )
        if extra not in extras:
            extras.append(extra)
        return f"{path}[{','.join(extras)}]"
    requirement = re.match(r"([A-Za-z0-9_.-]+)(?:\[([^]]*)\])?(.*)", source)
    if not requirement:
        raise ValueError("Unsupported package source")
    extras = [extra for extra in (requirement[2] or "").split(",") if extra]
    if extra not in extras:
        extras.append(extra)
    return f"{requirement[1]}[{','.join(extras)}]{requirement[3]}"


def _package_command(python: Path, source: str, backend: str) -> list[str]:
    return [
        str(python),
        "-I",
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--no-input",
        "--no-user",
        _package_source(source, backend),
    ]


def _package_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "PIP_TARGET",
        "PIP_PREFIX",
        "PIP_USER",
        "PIP_ROOT",
        "PIP_PYTHON",
        "PYTHONHOME",
        "PYTHONPATH",
    ):
        environment.pop(name, None)
    # pip documents os.devnull as disabling system, user and venv config files.
    environment["PIP_CONFIG_FILE"] = os.devnull
    return environment


def update_package(
    source: str,
    python: str | Path,
    *,
    backend: str = "native",
    dry_run: bool = False,
    runner: Callable | None = None,
) -> list[str]:
    """Upgrade the selected venv with an argument array, never a shell command.

    Global interpreters are rejected even in dry runs. Package installation must
    succeed before the CLI changes any client configurations.
    """
    python = _absolute(python)
    _virtual_environment(python)
    command = _package_command(python, source, backend)
    if not dry_run:
        (runner or subprocess.run)(
            command, check=True, stdout=sys.stderr, env=_package_environment()
        )
    return command


def ensure_environment(
    environment: str | Path,
    *,
    source: str = DEFAULT_SOURCE,
    python: str | Path | None = None,
    backend: str = "native",
    platform: str | None = None,
    dry_run: bool = False,
    runner: Callable | None = None,
) -> tuple[Path, list[list[str]]]:
    """Create or upgrade an explicitly requested private venv."""
    directory = _absolute(environment)
    selected_python = environment_python(directory, platform=platform)
    exists = (directory / "pyvenv.cfg").is_file()
    if (
        directory.exists()
        and not exists
        and (not directory.is_dir() or any(directory.iterdir()))
    ):
        raise ValueError(f"Refusing to overwrite a non-venv directory: {directory}")
    commands = []
    command = _package_command(selected_python, source, backend)
    if not exists:
        commands.append(
            [
                str(_absolute(python or sys.executable)),
                "-I",
                "-m",
                "venv",
                str(directory),
            ]
        )
        if not dry_run:
            (runner or subprocess.run)(
                commands[0], check=True, stdout=sys.stderr, env=_package_environment()
            )
    if not (dry_run and not exists):
        command = update_package(
            source, selected_python, backend=backend, dry_run=dry_run, runner=runner
        )
    commands.append(command)
    return selected_python, commands


def build_parser(operation: str = "install") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=f"ida-mcp-server {operation}",
        description=(
            "Install IDA MCP client configuration"
            if operation == "install"
            else "Upgrade IDA MCP in an isolated environment and refresh client configuration"
        ),
    )
    parser.add_argument(
        "--client",
        "--clients",
        action="extend",
        nargs="+",
        default=None,
        help="Client names or comma lists; default: all",
    )
    parser.add_argument("--home", type=Path, help="Configuration home directory")
    parser.add_argument(
        "--python", type=Path, help="Absolute server interpreter (default: this Python)"
    )
    parser.add_argument("--backend", choices=("native", "nexus"), default=None)
    parser.add_argument("--ida-dir", type=Path)
    parser.add_argument(
        "--tool-profile", choices=("compact", "legacy", "full"), default=None
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        help="Nexus idle timeout in seconds; 0 disables it",
    )
    parser.add_argument("--agent", help="Override the client label in server traces")
    parser.add_argument("--session-log", nargs="?", const="auto", default=None)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated settings without changing files or packages",
    )
    parser.add_argument(
        "--hooks",
        action="store_true",
        help="Install transcript hooks/plugins for Claude Code, supported Codex CLI, OpenCode and ZCode; review client hooks and start a new session",
    )
    parser.add_argument(
        "--venv",
        nargs="?",
        type=Path,
        const=Path("~/.local/share/ida-mcp-stdio/venv"),
        help="Install into this private environment; omit path to use ~/.local/share/ida-mcp-stdio/venv",
    )
    parser.add_argument(
        "--source", default=DEFAULT_SOURCE, help="Package source (default: GitHub main)"
    )
    parser.add_argument(
        "--gui-plugin",
        action="store_true",
        help="Install the official IDA 9.4+ Nexus GUI provider through HCLI",
    )
    parser.add_argument(
        "--gui-hcli",
        type=Path,
        help="HCLI executable; defaults to the server environment or PATH",
    )
    parser.add_argument(
        "--gui-ida-user-dir",
        type=Path,
        help="IDA user directory for GUI plugin installation",
    )
    parser.add_argument(
        "--gui-python", type=Path, help="Existing GUI IDAPython venv interpreter"
    )
    parser.add_argument(
        "--gui-create-environment",
        action="store_true",
        help="Allow HCLI to create and configure the GUI Python environment",
    )
    parser.add_argument(
        "--gui-environment",
        type=Path,
        help="GUI environment directory (requires --gui-create-environment)",
    )
    parser.add_argument(
        "--gui-no-configure-environment",
        action="store_true",
        help="Create GUI venv without persisting its login environment",
    )
    parser.add_argument(
        "--gui-timeout",
        type=float,
        help="Timeout per HCLI command, in seconds (default: 300)",
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    home: str | Path | None = None,
    python: str | Path | None = None,
    platform: str | None = None,
    operation: str = "install",
) -> int:
    if operation not in ("install", "update"):
        raise ValueError("Operation must be install or update")
    parser = build_parser(operation)
    args = parser.parse_args(argv)
    try:
        if not args.gui_plugin and any(
            (
                args.gui_hcli,
                args.gui_ida_user_dir,
                args.gui_python,
                args.gui_create_environment,
                args.gui_environment,
                args.gui_no_configure_environment,
                args.gui_timeout is not None,
            )
        ):
            raise ValueError("GUI options require --gui-plugin")
        clients = normalize_clients(args.client or "all")
        selected_home = _absolute(args.home or home or Path.home())
        settings = {}
        explicit_overrides = {
            name: getattr(args, name)
            for name in _ARGUMENT_NAMES.values()
            if getattr(args, name) is not None
        }
        for client in clients:
            options = {
                "backend": "native",
                "ida_dir": None,
                "tool_profile": "compact",
                "idle_timeout": None,
                "agent": None,
                "session_log": "auto",
            }
            if operation == "update":
                options.update(
                    _existing_options(client, home=selected_home, platform=platform)
                )
            for name in options:
                supplied = getattr(args, name)
                if supplied is not None:
                    options[name] = supplied
            settings[client] = options
        selected_python = _absolute(args.python or python or sys.executable)
        environment = args.venv
        if environment == Path("~/.local/share/ida-mcp-stdio/venv"):
            environment = selected_home / ".local" / "share" / SERVER_NAME / "venv"
        if environment is not None:
            config_python = environment_python(environment, platform=platform)
        else:
            config_python = selected_python
        # Parse every configuration before creating or upgrading an environment.
        hooks_supported = (
            _codex_hooks_supported() if args.hooks and "codex" in clients else False
        )
        results = install_clients(
            clients,
            home=selected_home,
            python=config_python,
            platform=platform,
            dry_run=True,
            client_settings=settings,
            hooks=args.hooks,
            codex_hooks_supported=hooks_supported,
            preserve_arguments=operation == "update",
            argument_overrides=explicit_overrides,
        )
        required_extras = {
            extra for result in results for extra in result.required_extras
        }
        gui_plan = None
        if args.gui_plugin:
            from .gui import plan_gui_install

            directories = {
                str(value["ida_dir"])
                for value in settings.values()
                if value["ida_dir"] is not None
            }
            if len(directories) != 1:
                raise ValueError("GUI deployment requires one explicit --ida-dir")
            executable = config_python.parent / (
                "hcli.exe" if (platform or sys.platform) == "win32" else "hcli"
            )
            will_provision = environment is not None or operation == "update"
            hcli = args.gui_hcli or (
                executable if executable.is_file() or will_provision else "hcli"
            )
            gui_plan = plan_gui_install(
                ida_dir=next(iter(directories)),
                hcli=hcli,
                ida_user_dir=args.gui_ida_user_dir,
                ida_python=args.gui_python,
                create_environment=args.gui_create_environment,
                environment=args.gui_environment,
                configure_environment=not args.gui_no_configure_environment,
                timeout=300 if args.gui_timeout is None else args.gui_timeout,
                platform=platform,
                allow_missing_hcli=will_provision and args.gui_hcli is None,
            )
            required_extras.update(("nexus", "gui"))
        package_backend = "nexus" if "nexus" in required_extras else "native"
        package_source = (
            _with_extra(args.source, "http")
            if "http" in required_extras
            else args.source
        )
        if "gui" in required_extras:
            package_source = _with_extra(package_source, "gui")
        commands = []
        if environment is not None:
            _, commands = ensure_environment(
                environment,
                source=package_source,
                python=selected_python,
                backend=package_backend,
                platform=platform,
                dry_run=args.dry_run,
            )
        elif operation == "update":
            commands = [
                update_package(
                    package_source,
                    selected_python,
                    backend=package_backend,
                    dry_run=args.dry_run,
                )
            ]
        if gui_plan is not None:
            from .gui import execute_gui_install

            execute_gui_install(gui_plan, dry_run=args.dry_run)
            if args.dry_run:
                print(
                    json.dumps(
                        {
                            "operation": "gui-install",
                            "commands": gui_plan.commands,
                            "ida_dir": str(gui_plan.ida_dir),
                            "ida_user_dir": str(gui_plan.ida_user_dir),
                            "gui_python": (
                                str(gui_plan.ida_python)
                                if gui_plan.ida_python
                                else None
                            ),
                            "configuration_files": [
                                str(path) for path in gui_plan.configuration_files
                            ],
                        },
                        ensure_ascii=False,
                    )
                )
            else:
                print(
                    f"Installed official GUI provider in {gui_plan.ida_user_dir / 'plugins'}"
                )
        if not args.dry_run:
            results = install_clients(
                clients,
                home=selected_home,
                python=config_python,
                platform=platform,
                client_settings=settings,
                hooks=args.hooks,
                codex_hooks_supported=hooks_supported,
                preserve_arguments=operation == "update",
                argument_overrides=explicit_overrides,
            )
        elif commands:
            print(
                json.dumps(
                    {
                        "operation": (
                            "package-upgrade"
                            if operation == "update"
                            else "environment-install"
                        ),
                        "commands": commands,
                    },
                    ensure_ascii=False,
                )
            )
    except GuiInstallError as exc:
        detail = str(exc)
        if exc.stderr.strip():
            detail += "\n" + exc.stderr.strip()[:4096]
        if exc.may_have_changes and "external changes may remain" not in detail:
            detail += "\nHCLI external changes may remain."
        parser.error(detail)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    for result in results:
        if args.dry_run:
            preview = dict(result.server)
            report = {
                "client": result.client,
                "path": str(result.path),
                "changed": result.changed,
            }
            if operation == "update" and not result.client.endswith("-hooks"):
                preview.pop("args", None)
                if isinstance(preview.get("command"), list):
                    preview["command"] = preview["command"][:1]
                report["server_patch"] = preview
                report["preserve_existing_arguments"] = True
                report["argument_updates"] = {
                    name: str(value) if isinstance(value, Path) else value
                    for name, value in explicit_overrides.items()
                }
            else:
                report["server"] = preview
            if result.hook_settings is not None:
                report["hooks"] = result.hook_settings
            print(
                json.dumps(
                    report,
                    ensure_ascii=False,
                )
            )
        else:
            print(
                f"{'Installed' if result.changed else 'Unchanged'} {result.client}: {result.path}"
            )
            if result.backup:
                print(f"  Backup: {result.backup}")
    if args.hooks and "codex" in clients:
        if hooks_supported:
            print(
                "Codex hooks require review: open /hooks in Codex to trust the new or changed definition."
            )
        else:
            print(
                "Skipped Codex hooks: an enabled, stable hooks capability was not detected (Windows hooks require manual setup)."
            )
    if args.hooks and "opencode" in clients:
        print(
            "OpenCode plugin: review the generated local plugin and start a new session; supports the V1 plugin client.session.messages contract (checked with OpenCode 1.15.13 / plugin SDK 1.14.40)."
        )
    if args.hooks and "zcode" in clients:
        print(
            "ZCode hooks require review: inspect Settings > Hooks, enable hooks if disabled, and start a new session. Only hook-provided current-session data is persisted; missing token/cost data stays unavailable."
        )
    if args.hooks and "claude-desktop" in clients:
        print(
            "Skipped Claude Desktop hooks: no supported transcript hook/plugin contract is available; attach an explicit transcript when needed."
        )
    if args.gui_plugin and not args.dry_run:
        print(
            "Restart IDA with the selected IDAPython environment; GUI sharing uses --backend nexus."
        )
    return 0


def update_main(
    argv: list[str] | None = None,
    *,
    home: str | Path | None = None,
    python: str | Path | None = None,
    platform: str | None = None,
) -> int:
    return main(argv, home=home, python=python, platform=platform, operation="update")
