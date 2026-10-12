"""Repeatable read-only IDA tasks and separately recorded agent usage."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .client import IDAMCPClient, MCPConnectionError, MCPError, MCPToolError
from .transcripts import load_transcript

TASKS = {
    "functions": """import idautils, ida_funcs, ida_name
rows = []
for ea in list(idautils.Functions())[:32]:
    function = ida_funcs.get_func(ea)
    callees = set()
    for head in list(idautils.Heads(function.start_ea, function.end_ea))[:256]:
        for target in idautils.CodeRefsFrom(head, False):
            callee = ida_funcs.get_func(target)
            if callee and callee.start_ea != function.start_ea:
                callees.add(ida_name.get_name(callee.start_ea))
    rows.append({'name': ida_name.get_name(ea), 'size': function.end_ea - function.start_ea, 'callees': sorted(callees)})
sorted(rows, key=lambda row: row['name'])""",
    "strings": """import idautils, itertools
sorted(str(row) for row in itertools.islice(idautils.Strings(), 32))""",
    "imports": """import ida_nalt
rows = []
def collect_import(ea, name, ordinal):
    if len(rows) >= 64:
        return False
    rows.append({'module': module, 'name': name, 'ordinal': ordinal})
    return True
for index in range(ida_nalt.get_import_module_qty()):
    module = ida_nalt.get_import_module_name(index)
    ida_nalt.enum_import_names(index, collect_import)
    if len(rows) >= 64:
        break
sorted(rows, key=lambda row: (row['module'] or '', row['name'] or '', row['ordinal']))""",
}
ENVIRONMENT_CODE = """import ida_kernwin, ida_loader, sys
{'ida_version': ida_kernwin.get_kernel_version(), 'worker_python': sys.version, 'file_type': ida_loader.get_file_type_name()}"""


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _batch_code() -> str:
    # Independent namespaces make the separate and batched tasks identical.
    return (
        "benchmark_result = {}\n"
        + "\n".join(
            (
                f"scope = {{}}\nexec({code.rsplit(chr(10), 1)[0]!r}, scope)\n"
                f"benchmark_result[{name!r}] = eval({code.rsplit(chr(10), 1)[1]!r}, scope)"
            )
            for name, code in TASKS.items()
        )
        + "\nbenchmark_result"
    )


class _RecordingClient(IDAMCPClient):
    def __init__(self, **kwargs):
        self.phase = "setup"
        self.measurements: list[dict] = []
        super().__init__(**kwargs)

    def _send_request(self, method, params=None, timeout=None):
        started = time.perf_counter()
        result = super()._send_request(method, params, timeout)
        self.measurements.append(
            {
                "phase": self.phase,
                "method": method,
                "seconds": time.perf_counter() - started,
                "request_params_bytes": len(_encoded(params or {})),
                "response_result_bytes": len(_encoded(result)),
            }
        )
        return result


def _execute(client: IDAMCPClient, instance: str, code: str) -> Any:
    executed = client.call_tool(
        "execute_python",
        {"code": code, "instance_id": instance, "timeout": 360},
        timeout=390,
    )
    if not isinstance(executed, dict) or executed.get("error"):
        raise RuntimeError(f"Analysis failed: {executed}")
    if executed.get("output_truncated"):
        raise RuntimeError("Analysis output was truncated")
    return executed["result"]


def run_benchmark(
    binary: Path,
    *,
    label: str,
    mode: str = "batch",
    backend: str = "native",
    ida_dir: str | None = None,
    server_command: list[str] | None = None,
) -> dict:
    """Inspect a temporary binary copy through any compatible stdio MCP server.

    Opening a binary may create a database; the copy prevents changes to the
    original. Existing IDBs are rejected because their companion files and
    prior analysis state would change the workload.
    """
    binary = Path(binary).expanduser().resolve()
    if not binary.is_file() or binary.suffix.lower() in {".idb", ".i64", ".id0"}:
        raise ValueError("binary must be an existing executable, not an IDB")
    if mode not in {"batch", "separate"} or backend not in {"native", "nexus"}:
        raise ValueError("invalid benchmark mode or backend")
    if not isinstance(label, str) or not label.strip():
        raise ValueError("label must be nonempty")
    if server_command is not None and (
        not isinstance(server_command, list)
        or not server_command
        or any(
            not isinstance(arg, str) or not arg or "\x00" in arg
            for arg in server_command
        )
    ):
        raise ValueError("server command must be a nonempty JSON array of strings")
    server_args = ["--backend", backend]
    if ida_dir:
        server_args.extend(["--ida-dir", ida_dir])
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="ida-mcp-benchmark-") as directory:
        scratch = Path(directory)
        copy = scratch / binary.name
        shutil.copyfile(binary, copy)
        binary_digest = _digest(copy)
        with _RecordingClient(
            tool_profile="compact",
            server_command=server_command,
            server_args=[] if server_command else server_args,
            process_env={"IDA_MCP_STDIO_STATE_DIR": str(scratch / "state")},
            timeout=390,
        ) as client:
            initialized = client.initialize()
            client.phase = "discovery"
            tools = client.list_tools()
            names = sorted(tool.get("name", "") for tool in tools)
            discovery = {
                "profile": (
                    "compact"
                    if names
                    == sorted(
                        (
                            "open_database",
                            "list_databases",
                            "save_database",
                            "close_database",
                            "execute_python",
                            "reference",
                        )
                    )
                    else "custom"
                ),
                "tool_names": names,
                "schema_sha256": hashlib.sha256(_encoded(tools)).hexdigest(),
            }
            client.phase = "open"
            opened = client.call_tool("open_database", {"path": str(copy)}, timeout=390)
            instance = opened.get("instance_id") if isinstance(opened, dict) else None
            if not instance:
                raise RuntimeError(f"Database could not be opened: {opened}")
            try:
                client.phase = "environment"
                environment = _execute(client, instance, ENVIRONMENT_CODE)
                client.phase = "workflow"
                result = (
                    _execute(client, instance, _batch_code())
                    if mode == "batch"
                    else {
                        name: _execute(client, instance, code)
                        for name, code in TASKS.items()
                    }
                )
                if not isinstance(result, dict) or set(result) != set(TASKS):
                    raise RuntimeError("Analysis returned an incomplete result")
                if not all(isinstance(value, list) for value in result.values()):
                    raise RuntimeError("Analysis results must be lists")
            finally:
                client.phase = "cleanup"
                closed = client.call_tool("close_database", {"instance_id": instance})
                if isinstance(closed, dict) and closed.get("error"):
                    raise RuntimeError(f"Database cleanup failed: {closed['error']}")
    workflow = [row for row in client.measurements if row["phase"] == "workflow"]
    return {
        "schema": 1,
        "label": label,
        "mode": mode,
        "backend": backend if not server_command else "external",
        "server_command": server_command,
        "server_info": initialized.get("serverInfo"),
        "discovery": discovery,
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "workload": {
            "task": "static-summary-v1",
            "task_sha256": hashlib.sha256(_encoded(TASKS)).hexdigest(),
            "binary_sha256": binary_digest,
            "binary_name": binary.name,
        },
        "environment": environment,
        "semantic_result": result,
        "measurements": {
            "total_seconds": time.perf_counter() - started,
            "workflow_seconds": sum(row["seconds"] for row in workflow),
            "workflow_requests": len(workflow),
            "workflow_request_params_bytes": sum(
                row["request_params_bytes"] for row in workflow
            ),
            "workflow_response_bytes": sum(
                row["response_result_bytes"] for row in workflow
            ),
            "tool_schema_bytes": len(_encoded(tools)),
        },
        "requests": client.measurements,
        "scope": "Scripted static analysis; timings include MCP calls, not LLM inference. JSON sizes exclude transport framing. No agent tokens or cost are inferred.",
    }


def _number(value: Any) -> bool:
    try:
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value >= 0
            and math.isfinite(value)
        )
    except OverflowError:
        return False


def compare_reports(baseline: dict, candidate: dict) -> dict:
    """Compare only equivalent tasks and IDA/Python environments."""
    for report in (baseline, candidate):
        if not isinstance(report, dict) or any(
            not isinstance(report.get(key), dict)
            for key in ("workload", "environment", "measurements")
        ):
            raise ValueError("benchmark report fields must be objects")
    if any(
        type(report.get("schema")) is not int or report["schema"] != 1
        for report in (baseline, candidate)
    ):
        raise ValueError("unsupported benchmark report schema")
    for section, keys in (
        ("host", ("platform", "python")),
        ("discovery", ("profile",)),
    ):
        for key in keys:
            left = baseline.get(section)
            right = candidate.get(section)
            if (
                not isinstance(left, dict)
                or not isinstance(right, dict)
                or not isinstance(left.get(key), str)
                or not left[key]
                or left[key] != right.get(key)
            ):
                raise ValueError(f"different or missing {section} provenance: {key}")
    tool_sets = []
    schema_digests = []
    for report in (baseline, candidate):
        names = report["discovery"].get("tool_names")
        if (
            not isinstance(names, list)
            or not all(isinstance(name, str) and name for name in names)
            or len(set(names)) != len(names)
        ):
            raise ValueError("invalid or missing discovery tool names")
        tool_sets.append(set(names))
        digest = report["discovery"].get("schema_sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("invalid or missing discovery schema digest")
        schema_digests.append(digest)
    if tool_sets[0] != tool_sets[1]:
        raise ValueError("different discovery tool names")
    for key in ("task_sha256", "binary_sha256"):
        first = baseline.get("workload", {}).get(key)
        second = candidate.get("workload", {}).get(key)
        if (
            not isinstance(first, str)
            or re.fullmatch(r"[0-9a-f]{64}", first) is None
            or first != second
        ):
            raise ValueError(f"different or missing workload {key}")
    for key in ("ida_version", "worker_python", "file_type"):
        first = baseline.get("environment", {}).get(key)
        second = candidate.get("environment", {}).get(key)
        if not isinstance(first, str) or not first or first != second:
            raise ValueError(f"different or missing environment {key}")
    result = baseline.get("semantic_result")
    if (
        not isinstance(result, dict)
        or set(result) != set(TASKS)
        or not all(isinstance(value, list) for value in result.values())
        or result != candidate.get("semantic_result")
    ):
        raise ValueError("different or missing semantic result")
    measurements = {}
    for key in ("workflow_seconds", "workflow_requests", "workflow_response_bytes"):
        first = baseline.get("measurements", {}).get(key)
        second = candidate.get("measurements", {}).get(key)
        if (
            not _number(first)
            or not _number(second)
            or (
                key != "workflow_seconds"
                and (type(first) is not int or type(second) is not int)
            )
        ):
            raise ValueError(f"invalid or missing measurement {key}")
        reduction = (1 - second / first) * 100 if first else None
        if reduction is not None and not math.isfinite(reduction):
            raise ValueError(f"measurement ratio exceeds finite numeric range: {key}")
        measurements[key] = {
            "baseline": first,
            "candidate": second,
            "reduction_percent": reduction,
        }
    return {
        "equivalent": True,
        "baseline": baseline.get("label"),
        "candidate": candidate.get("label"),
        "discovery": {
            "tool_names": sorted(tool_sets[0]),
            "baseline_schema_sha256": schema_digests[0],
            "candidate_schema_sha256": schema_digests[1],
            "schema_equal": schema_digests[0] == schema_digests[1],
        },
        "measurements": measurements,
        "scope": "Scripted workflow metrics only; no LLM token/cost saving claim. Repeat and alternate run order before interpreting timings.",
    }


def transcript_usage(path: Path, agent: str) -> dict:
    """Return actual recorded usage for one explicitly selected transcript."""
    if not Path(path).is_file():
        raise ValueError("transcript must name an existing file")
    transcript = load_transcript(Path(path), agent)
    return {
        "agent": agent,
        "usage": transcript["usage"],
        "task_seconds": transcript["task_seconds"],
        "warnings": transcript["warnings"],
        "scope": "The whole explicitly selected transcript; unrelated turns may be included. Missing cost and token fields remain unavailable.",
    }


def _output_path(path: Path) -> Path:
    path = Path(path).expanduser().absolute()
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"report already exists: {path}")
    for parent in path.parents:
        if parent.is_symlink():
            if (
                sys.platform == "darwin"
                and str(parent) in {"/tmp", "/var"}
                and str(parent.resolve()) == "/private" + str(parent)
            ):
                continue
            raise ValueError(f"Refusing symlinked report directory: {parent}")
    if not path.parent.is_dir():
        raise ValueError(f"report directory does not exist: {path.parent}")
    return path


def write_report(path: Path, report: dict) -> None:
    """Write a private report, refusing existing destinations and symlinks."""
    encoded = _encoded(report) + b"\n"
    fd = os.open(_output_path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ida-mcp-server benchmark")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser(
        "run", help="Run a repeatable read-only static analysis task"
    )
    run.add_argument("binary", type=Path)
    run.add_argument("--label", required=True)
    run.add_argument("--mode", choices=("batch", "separate"), default="batch")
    run.add_argument("--backend", choices=("native", "nexus"), default="native")
    run.add_argument("--ida-dir")
    run.add_argument(
        "--server-command",
        type=Path,
        help="JSON file containing an explicit stdio server argv",
    )
    compare = commands.add_parser(
        "compare", help="Compare task, environment and result before metrics"
    )
    compare.add_argument("baseline", type=Path)
    compare.add_argument("candidate", type=Path)
    usage = commands.add_parser(
        "usage", help="Read actual recorded agent usage, without estimates"
    )
    usage.add_argument("transcript", type=Path)
    usage.add_argument(
        "--agent", choices=("claude", "codex", "opencode", "zcode"), required=True
    )
    for command in (run, compare, usage):
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        args.output = _output_path(args.output)
        if args.command == "run":
            command = (
                json.loads(args.server_command.read_text())
                if args.server_command
                else None
            )
            if args.server_command is not None and not isinstance(command, list):
                raise ValueError(
                    "server command file must contain a JSON array of strings"
                )
            value = run_benchmark(
                args.binary,
                label=args.label,
                mode=args.mode,
                backend=args.backend,
                ida_dir=args.ida_dir,
                server_command=command,
            )
        elif args.command == "compare":
            value = compare_reports(
                json.loads(args.baseline.read_text()),
                json.loads(args.candidate.read_text()),
            )
        else:
            value = transcript_usage(args.transcript, args.agent)
        write_report(args.output, value)
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        TypeError,
        MCPError,
        MCPToolError,
        MCPConnectionError,
        TimeoutError,
    ) as exc:
        parser.error(str(exc))
    print(args.output.expanduser().absolute())
    return 0
