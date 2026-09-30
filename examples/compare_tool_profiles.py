"""Compare legacy and compact discovery and equivalent native analysis.

Run: python examples/compare_tool_profiles.py /path/to/binary --ida-dir /path/to/IDA
The JSON report includes schemas and complete request/response payloads. Payload
sizes use compact JSON with UTF-8 text, rather than transport framing. Token
counts are included only when the optional tiktoken package is installed.
Native sessions close without saving. Nexus sessions save on close because the
official Nexus API requires saving when a database is closed.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from ida_mcp_stdio import IDAMCPClient

WORKFLOW_CODE = (
    "functions = tools.list_funcs(count=3)\n"
    "disassembly = [tools.disasm(row['addr'], max_instructions=8) "
    "for row in functions['data']]\n"
    "imported = tools.imports(count=10)\n"
    "{'functions': functions, 'disassembly': disassembly, 'imports': imported}"
)


def get_tokenizer(encoding: str) -> Any:
    """Load the requested real tokenizer, or use byte counts if absent."""
    try:
        import tiktoken
    except ImportError:
        return None
    return tiktoken.get_encoding(encoding)


def measure_payload(value: Any, tokenizer: Any) -> dict[str, int]:
    """Measure one JSON payload; token counts never use an estimate."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    result = {"utf8_bytes": len(text.encode("utf-8"))}
    if tokenizer is not None:
        result["tokens"] = len(tokenizer.encode(text, disallowed_special=()))
    return result


class RecordingClient(IDAMCPClient):
    """Record each actual protocol request, including artifact page retrieval."""

    def __init__(self, *, tokenizer: Any = None, **kwargs):
        self.tokenizer = tokenizer
        self.phase = "setup"
        self.requests: list[dict] = []
        super().__init__(**kwargs)

    def _send_request(self, method, params=None, timeout=None):
        started = time.perf_counter()
        output = super()._send_request(method, params, timeout)
        elapsed = time.perf_counter() - started
        self.requests.append(
            {
                "phase": self.phase,
                "method": method,
                "params": params or {},
                "output": output,
                "params_size": measure_payload(params or {}, self.tokenizer),
                "output_size": measure_payload(output, self.tokenizer),
                "elapsed_seconds": elapsed,
            }
        )
        return output


def check_semantic_result(result: dict) -> None:
    """Reject helper errors before reporting equivalent successful analysis."""
    for name, outputs in (
        ("functions", [result["functions"]]),
        ("disassembly", result["disassembly"]),
        ("imports", [result["imports"]]),
    ):
        for output in outputs:
            if output.get("error"):
                raise RuntimeError(f"{name} failed: {output['error']}")


def _sum_measurements(values: list[dict[str, int]], tokenizer: Any) -> dict[str, int]:
    keys = ("utf8_bytes", "tokens") if tokenizer is not None else ("utf8_bytes",)
    return {key: sum(value[key] for value in values) for key in keys}


def run_profile(
    profile: str,
    binary: str,
    ida_dir: str | None = None,
    *,
    backend: str = "native",
    tokenizer: Any = None,
) -> dict:
    """Run the workflow; close native unsaved and Nexus with its required save."""
    if profile not in {"legacy", "compact"}:
        raise ValueError("profile must be legacy or compact")
    server_args = ["--backend", backend]
    if ida_dir:
        server_args.extend(["--ida-dir", ida_dir])
    started = time.perf_counter()
    with RecordingClient(
        tool_profile=profile, server_args=server_args, timeout=390, tokenizer=tokenizer
    ) as client:
        client.initialize()
        client.phase = "discovery"
        schemas = client.list_tools()
        if profile == "compact":
            client.reference("list_funcs disasm imports")
        client.phase = "open"
        target = client.open_database(binary)
        if not target.get("instance_id"):
            raise RuntimeError(f"Database could not be opened: {target}")
        try:
            client.phase = "workflow"
            if profile == "legacy":
                functions = client.call_tool("list_funcs", {"count": 3})
                disassembly = [
                    client.call_tool(
                        "disasm", {"addr": row["addr"], "max_instructions": 8}
                    )
                    for row in functions["data"]
                ]
                result = {
                    "functions": functions,
                    "disassembly": disassembly,
                    "imports": client.call_tool("imports", {"count": 10}),
                }
            else:
                executed = client.execute_python(
                    WORKFLOW_CODE,
                    instance_id=target["instance_id"],
                    persist_globals=False,
                )
                if executed.get("error"):
                    raise RuntimeError(f"execute_python failed: {executed['error']}")
                if executed.get("output_truncated"):
                    raise RuntimeError("execute_python output was truncated")
                result = executed["result"]
            check_semantic_result(result)
        finally:
            client.phase = "cleanup"
            closed = client.close_database(
                target["instance_id"], save=backend == "nexus"
            )
            if closed.get("error"):
                raise RuntimeError(f"Database cleanup failed: {closed['error']}")

    calls = [
        request for request in client.requests if request["method"] == "tools/call"
    ]
    resources = [
        request for request in client.requests if request["method"] == "resources/read"
    ]
    phases = {request["phase"] for request in client.requests}
    return {
        "profile": profile,
        "backend": backend,
        "server_args": server_args,
        "elapsed_seconds": time.perf_counter() - started,
        "phase_request_counts": {
            phase: sum(request["phase"] == phase for request in client.requests)
            for phase in sorted(phases)
        },
        "phase_elapsed_seconds": {
            phase: sum(
                request["elapsed_seconds"]
                for request in client.requests
                if request["phase"] == phase
            )
            for phase in sorted(phases)
        },
        "request_count": len(client.requests),
        "workflow_request_count": sum(
            request["phase"] == "workflow" for request in client.requests
        ),
        "tool_count": len(schemas),
        "tool_schemas": schemas,
        "schemas": measure_payload(schemas, tokenizer),
        "tool_arguments": _sum_measurements(
            [
                measure_payload(request["params"]["arguments"], tokenizer)
                for request in calls
            ],
            tokenizer,
        ),
        "tool_outputs": _sum_measurements(
            [request["output_size"] for request in calls], tokenizer
        ),
        "resource_outputs": _sum_measurements(
            [request["output_size"] for request in resources], tokenizer
        ),
        "semantic_result": result,
        "requests": client.requests,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "--ida-dir", help="IDA installation directory forwarded to the server"
    )
    parser.add_argument("--backend", choices=("native", "nexus"), default="native")
    parser.add_argument(
        "--encoding", default="o200k_base", help="Optional tiktoken encoding"
    )
    args = parser.parse_args(argv)
    if not args.binary.is_file():
        parser.error("binary must name an existing file")
    report: dict[str, Any] = {
        "binary": str(args.binary.resolve()),
        "measurement": "Compact JSON UTF-8 payload bytes; tokens sum separately encoded payloads.",
        "workflow": {"function_limit": 3, "instruction_limit": 8, "import_limit": 10},
        "profiles": {},
    }
    try:
        tokenizer = get_tokenizer(args.encoding)
        report["tokenizer"] = (
            {"name": "tiktoken", "encoding": args.encoding}
            if tokenizer is not None
            else {"available": False}
        )
        for profile in ("legacy", "compact"):
            report["profiles"][profile] = run_profile(
                profile,
                report["binary"],
                args.ida_dir,
                backend=args.backend,
                tokenizer=tokenizer,
            )
        report["semantic_results_equal"] = (
            report["profiles"]["legacy"]["semantic_result"]
            == report["profiles"]["compact"]["semantic_result"]
        )
        status = 0 if report["semantic_results_equal"] else 1
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        status = 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
