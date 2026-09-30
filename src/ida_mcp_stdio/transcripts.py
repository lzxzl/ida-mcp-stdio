"""Read recorded agent formats; never derive cost from model price tables."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path


def _invalid_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON number: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"Non-finite JSON number: {value}")
    return parsed


def read_records(path: Path) -> tuple[list[dict], list[str]]:
    """Read JSON or JSONL, retaining valid records around malformed/truncated lines."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError) as exc:
        return [], [f"Cannot read {path}: {exc}"]
    try:
        value = json.loads(
            text, parse_constant=_invalid_constant, parse_float=_finite_float
        )
    except ValueError:
        value = None
    if isinstance(value, dict):
        return [value], []
    if isinstance(value, list):
        records = [item for item in value if isinstance(item, dict)]
        skipped = len(value) - len(records)
        return records, [f"Skipped {skipped} non-object records"] if skipped else []
    records, warnings = [], []
    for index, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(
                line, parse_constant=_invalid_constant, parse_float=_finite_float
            )
            if not isinstance(record, dict):
                raise ValueError("record is not an object")
            records.append(record)
        except ValueError:
            warnings.append(f"Skipped malformed or truncated record at line {index}")
    return records, warnings


def skipped_records(warnings: Iterable[str]) -> int:
    count = 0
    for warning in warnings:
        if warning.startswith("Skipped"):
            value = warning.split()[1]
            count += int(value) if value.isdecimal() else 1
    return count


def parse_timestamp(value: object) -> datetime | None:
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(
                value / 1000 if value > 10**11 else value, timezone.utc
            )
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return (
                parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
            )
    except (ValueError, OSError, OverflowError):
        pass
    return None


def number(value: object) -> float | int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, float) and math.isfinite(value) and value >= 0:
        return value
    return None


def blank_usage(scope: str = "recorded messages") -> dict:
    return {
        "input": 0,
        "output": 0,
        "cache_read": 0,
        "cache_write": 0,
        "reasoning": 0,
        "total": None,
        "has_tokens": False,
        "cost": None,
        "cost_partial": False,
        "scope": scope,
        "unavailable": [],
        "warnings": [],
    }


def recorded_usage(raw: object, cost: object = None) -> dict:
    usage = blank_usage()
    if not isinstance(raw, dict):
        raw = {}
    aliases = {
        "input": ("input_tokens", "inputTokens", "input"),
        "output": ("output_tokens", "outputTokens", "output"),
        "cache_read": (
            "cache_read_input_tokens",
            "cached_input_tokens",
            "cacheReadTokens",
            "cache_read",
        ),
        "cache_write": (
            "cache_creation_input_tokens",
            "cacheWriteTokens",
            "cache_write",
        ),
        "reasoning": ("reasoning_output_tokens", "reasoningTokens", "reasoning"),
        "total": ("total_tokens", "totalTokens", "total"),
    }
    for target, keys in aliases.items():
        for key in keys:
            value = raw.get(key)
            if isinstance(value, dict):
                value = value.get("tokenCount")
            value = number(value)
            if value is not None:
                usage[target] = value
                usage["has_tokens"] = True
                break
    cache = raw.get("cache")
    if isinstance(cache, dict):
        for key in ("read", "write"):
            value = number(cache.get(key))
            if value is not None:
                usage[f"cache_{key}"] = value
                usage["has_tokens"] = True
    if cost is None:
        cost = raw.get("cost", raw.get("cost_usd"))
    if isinstance(cost, dict):
        cost = cost.get("total")
    usage["cost"] = number(cost)
    return usage


def sum_usage(usages: Iterable[dict], scope: str = "recorded messages") -> dict:
    result = blank_usage(scope)
    entries = list(usages)
    result["warnings"] = list(
        dict.fromkeys(w for entry in entries for w in entry.get("warnings", []))
    )
    for key in (
        "input",
        "output",
        "cache_read",
        "cache_write",
        "reasoning",
        "total",
        "cost",
    ):
        optional = key in ("total", "cost")
        unavailable = any(
            key in entry.get("unavailable", [])
            or (not optional and entry.get(key, 0) is None)
            for entry in entries
        )
        values = [entry.get(key, None if optional else 0) for entry in entries]
        values = [value for value in values if value is not None]
        if not unavailable and values:
            try:
                aggregate = sum(values)
                # Integers are exact in Python, but the dashboard's JSON consumer
                # also needs a finite numeric representation.
                unavailable = number(aggregate) is None or not math.isfinite(aggregate)
            except (OverflowError, TypeError, ValueError):
                unavailable = True
            if not unavailable:
                result[key] = aggregate
        if unavailable:
            result[key] = None
            result["unavailable"].append(key)
            warning = f"Unavailable {key} usage aggregate: recorded values exceed finite numeric range"
            if warning not in result["warnings"]:
                result["warnings"].append(warning)
    result["has_tokens"] = any(entry.get("has_tokens") for entry in entries)
    result["cost_partial"] = result["cost"] is not None and any(
        x.get("cost_partial") or (x.get("cost") is None and x.get("has_tokens"))
        for x in entries
    )
    return result


def iter_transcript_references(records: Iterable[dict]) -> Iterator[tuple[str, str]]:
    """Only explicit transcript metadata links authorize transcript access."""
    seen = set()
    for record in records:
        containers = [record]
        for key in ("session", "metadata", "_meta"):
            value = record.get(key)
            if isinstance(value, dict):
                containers.append(value)
        arguments = record.get("arguments")
        if isinstance(arguments, dict) and isinstance(arguments.get("_meta"), dict):
            containers.append(arguments["_meta"])
        for container in containers:
            for key, value in container.items():
                if (
                    key.endswith("_session_path")
                    and isinstance(value, str)
                    and value.strip()
                    and "\x00" not in value
                ):
                    reference = (key.removesuffix("_session_path"), value)
                    if reference not in seen:
                        seen.add(reference)
                        yield reference


def resolve_reference(value: str, semantic_path: Path) -> Path:
    path = Path(value).expanduser()
    return (path if path.is_absolute() else semantic_path.parent / path).resolve()


def semantic_records(records: Iterable[dict]) -> bool:
    return any(
        isinstance(r.get("event"), str)
        and (
            (isinstance(r.get("session_id"), str) and bool(r["session_id"]))
            or (isinstance(r.get("mcp_server_id"), str) and bool(r["mcp_server_id"]))
        )
        for r in records
    )


def canonical_agent(kind: str) -> str:
    value = kind.lower()
    return {
        "claudecode": "claude",
        "claude-code": "claude",
        "claude_code": "claude",
    }.get(value, value)


def session_files(state_dir: Path) -> list[Path]:
    root = state_dir.expanduser().resolve()
    candidates = [root] if root.is_file() else sorted(root.rglob("*.jsonl"))
    return [
        p
        for p in candidates
        if p.is_file() and not p.is_symlink() and semantic_records(read_records(p)[0])
    ]


def _item(
    record: dict,
    kind: str = "raw",
    text: object = "",
    role: str = "",
    tool: str = "",
    call_id: object = None,
    timestamp: object = None,
) -> dict:
    ts = (
        timestamp
        if timestamp is not None
        else record.get("timestamp", record.get("ts"))
    )
    return {
        "timestamp": ts,
        "kind": kind,
        "role": role,
        "text": (
            str(text) if isinstance(text, str) else json.dumps(text, ensure_ascii=False)
        ),
        "tool": tool,
        "call_id": call_id,
        "raw": record,
    }


def _key(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _content_items(record: dict, message: dict, timestamp: object = None) -> list[dict]:
    role = str(message.get("role", record.get("type", "message")))
    content = message.get("content", "")
    if isinstance(content, str):
        return [_item(record, role, content, role, timestamp=timestamp)]
    items = []
    for part in content if isinstance(content, list) else [content]:
        if not isinstance(part, dict):
            items.append(_item(record, "raw", part, role, timestamp=timestamp))
            continue
        kind = part.get("type", "raw")
        text = part.get(
            "text", part.get("thinking", part.get("content", part.get("input", part)))
        )
        items.append(
            _item(
                record,
                str(kind),
                text,
                role,
                str(part.get("name", "")),
                part.get("id", part.get("tool_use_id")),
                timestamp,
            )
        )
    return items


def _claude(records: list[dict]) -> tuple[list[dict], dict]:
    items, usages = [], {}
    for index, record in enumerate(records):
        message = record.get("message")
        if not isinstance(message, dict):
            items.append(_item(record, text=record))
            continue
        items.extend(_content_items(record, message))
        if isinstance(message.get("usage"), dict):
            usages[_key(message.get("id", index))] = recorded_usage(
                message["usage"], message.get("cost")
            )
    return items, sum_usage(usages.values())


def _codex(records: list[dict]) -> tuple[list[dict], dict]:
    items, usage = [], blank_usage("whole transcript")
    for record in records:
        payload = record.get("payload")
        if not isinstance(payload, dict):
            items.append(_item(record, text=record))
            continue
        kind = payload.get("type", "raw")
        if kind == "token_count":
            info = payload.get("info")
            raw = info.get("total_token_usage") if isinstance(info, dict) else None
            if isinstance(raw, dict):
                usage = recorded_usage(raw)
                usage["scope"] = "whole transcript"
        text = payload.get(
            "message",
            payload.get(
                "text", payload.get("output", payload.get("arguments", payload))
            ),
        )
        if kind == "message":
            items.extend(_content_items(record, payload))
        else:
            items.append(
                _item(
                    record,
                    str(kind),
                    text,
                    str(payload.get("role", "user" if kind == "user_message" else "")),
                    str(payload.get("name", "")),
                    payload.get("call_id"),
                )
            )
    return items, usage


def _opencode(records: list[dict]) -> tuple[list[dict], dict]:
    messages = []
    for record in records:
        messages.extend(
            record["messages"] if isinstance(record.get("messages"), list) else [record]
        )
    items, usages = [], {}
    for index, record in enumerate(messages):
        if not isinstance(record, dict):
            continue
        info = record.get("info", record)
        if not isinstance(info, dict):
            info = {}
        time = info.get("time") if isinstance(info.get("time"), dict) else {}
        timestamp = time.get("created")
        parts = record.get("parts")
        parts = parts if isinstance(parts, list) else []
        for part in parts if isinstance(parts, list) else []:
            if not isinstance(part, dict):
                continue
            state = part.get("state") if isinstance(part.get("state"), dict) else {}
            kind = str(part.get("type", "raw"))
            items.append(
                _item(
                    record,
                    kind,
                    part.get("text", state or part),
                    str(info.get("role", "")),
                    str(part.get("tool", "")),
                    part.get("callID"),
                    timestamp,
                )
            )
        if info.get("role") == "assistant" and time.get("completed") is not None:
            items.append(
                _item(
                    record,
                    "assistant_complete",
                    "",
                    "assistant",
                    timestamp=time["completed"],
                )
            )
        key = _key(info.get("id", index))
        if isinstance(info.get("tokens"), dict) or number(info.get("cost")) is not None:
            usages[key] = recorded_usage(info.get("tokens"), info.get("cost"))
        else:
            usages[key] = sum_usage(
                recorded_usage(p.get("tokens"), p.get("cost"))
                for p in parts
                if isinstance(p, dict) and p.get("type") == "step-finish"
            )
        if not parts:
            items.append(_item(record, "raw", record, timestamp=timestamp))
    return items, sum_usage(usages.values())


def _zcode(records: list[dict]) -> tuple[list[dict], dict]:
    items, usages, prompts = [], {}, set()
    for index, record in enumerate(records):
        if record.get("type") != "model_io":
            items.append(_item(record, text=record))
            continue
        request, response = record.get("request"), record.get("response")
        request = request if isinstance(request, dict) else {}
        response = response if isinstance(response, dict) else {}
        for message in (
            request.get("messages", [])
            if isinstance(request.get("messages"), list)
            else []
        ):
            if not isinstance(message, dict) or message.get("role") != "user":
                continue
            key = (_key(record.get("turnId")), _key(message))
            if key not in prompts:
                prompts.add(key)
                items.extend(_content_items(record, message, record.get("startedAt")))
        for key, kind in (("reasoningText", "thinking"), ("text", "assistant")):
            if response.get(key):
                items.append(
                    _item(
                        record,
                        kind,
                        response[key],
                        "assistant",
                        timestamp=record.get("completedAt"),
                    )
                )
        for call in (
            response.get("toolCalls", [])
            if isinstance(response.get("toolCalls"), list)
            else []
        ):
            if isinstance(call, dict):
                items.append(
                    _item(
                        record,
                        "tool_use",
                        call.get("input", call.get("arguments", call)),
                        "assistant",
                        str(call.get("toolName", call.get("name", ""))),
                        call.get("toolCallId", call.get("id")),
                        record.get("completedAt"),
                    )
                )
        usages[
            (_key(record.get("requestId", index)), _key(record.get("attempt", 0)))
        ] = recorded_usage(response.get("usage"), response.get("cost"))
        if not response:
            items.append(_item(record, text=record))
    return items, sum_usage(usages.values())


def _copilot(records: list[dict]) -> tuple[list[dict], dict]:
    items, usage = [], blank_usage("whole transcript")
    for record in records:
        data = record.get("data") if isinstance(record.get("data"), dict) else {}
        kind = str(record.get("type", "raw"))
        items.append(
            _item(
                record,
                kind,
                data.get("content", data.get("message", data)),
                (
                    "user"
                    if kind == "user.message"
                    else "assistant" if kind.startswith("assistant.") else ""
                ),
                str(data.get("toolName", "")),
                data.get("toolCallId"),
            )
        )
        if kind == "session.shutdown" and isinstance(data.get("tokenDetails"), dict):
            usage = recorded_usage(data["tokenDetails"], data.get("cost"))
            usage["scope"] = "whole transcript"
    return items, usage


TranscriptParser = Callable[[list[dict]], tuple[list[dict], dict]]
_PARSERS: dict[str, TranscriptParser] = {
    "claude": _claude,
    "claudecode": _claude,
    "codex": _codex,
    "opencode": _opencode,
    "zcode": _zcode,
    "copilot": _copilot,
}


def register_parser(kind: str, parser: TranscriptParser) -> None:
    """Register an additional recorded format; unknown formats retain raw records."""
    _PARSERS[canonical_agent(kind)] = parser


def _task_seconds(items: list[dict], records: list[dict], kind: str) -> float | None:
    intervals = []
    if kind == "zcode":
        for record in records:
            start, end = parse_timestamp(record.get("startedAt")), parse_timestamp(
                record.get("completedAt")
            )
            if start and end and end >= start:
                intervals.append((start, end))
    else:
        start = end = None
        for item in sorted(
            items,
            key=lambda x: parse_timestamp(x["timestamp"])
            or datetime.min.replace(tzinfo=timezone.utc),
        ):
            timestamp = parse_timestamp(item["timestamp"])
            if timestamp is None:
                continue
            prompt = item["role"] == "user" and item["kind"] != "tool_result"
            work = item["role"] == "assistant" or item["kind"] in {
                "tool_use",
                "tool_result",
                "function_call",
                "function_call_output",
                "custom_tool_call",
                "custom_tool_call_output",
                "reasoning",
                "agent_message",
                "agent_reasoning",
                "mcp_tool_call_end",
                "task_complete",
                "task_aborted",
                "turn_aborted",
                "tool.execution_start",
                "tool.execution_complete",
                "model.model_call_success",
                "model.turn_ended",
            }
            if prompt:
                if start and end:
                    intervals.append((start, end))
                start, end = timestamp, None
            elif start and work:
                end = timestamp
        if start and end:
            intervals.append((start, end))
    if not intervals:
        return None
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return sum((end - start).total_seconds() for start, end in merged)


def load_transcript(path: Path, kind: str) -> dict:
    records, warnings = read_records(path)
    parser = _PARSERS.get(canonical_agent(kind))
    if parser is None:
        items = [_item(record, text=record) for record in records]
        usage = blank_usage()
        warnings.append(f"Unrecognized agent format: {kind}; raw records retained")
    else:
        items, usage = parser(records)
    warnings.extend(usage.get("warnings", []))
    return {
        "kind": kind,
        "path": str(path),
        "items": items,
        "usage": usage,
        "task_seconds": _task_seconds(items, records, kind),
        "warnings": warnings,
        "skipped_records": skipped_records(warnings),
    }
