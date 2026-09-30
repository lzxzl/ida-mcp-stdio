from __future__ import annotations

import json
import subprocess
import sys

from ida_mcp_stdio import dashboard


def test_print_config_and_doctor_do_not_import_ida():
    config = subprocess.run(
        [sys.executable, "-m", "ida_mcp_stdio", "--print-config"],
        capture_output=True,
        text=True,
        check=True,
    )
    result = json.loads(config.stdout)["mcpServers"]["ida-mcp-stdio"]
    assert result["command"] == sys.executable
    assert "--tool-profile" in result["args"]
    doctor = subprocess.run(
        [sys.executable, "-m", "ida_mcp_stdio", "--doctor"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(doctor.stdout)["backend"] == "native"


def test_dashboard_escapes_log_text_and_filters_events(tmp_path):
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        json.dumps(
            {
                "event": "tool_start",
                "tool": "execute_python",
                "arguments": {"code": "</script><script>alert(1)</script>"},
            }
        )
        + "\n"
    )
    output = tmp_path / "dashboard.html"
    dashboard.export_dashboard(trace, output)
    content = output.read_text()
    assert "<script>alert(1)</script>" not in content
    assert "execute_python" in content
    assert 'type="search"' in content


def test_http_refuses_non_loopback_before_importing_sdk():
    import pytest

    from ida_mcp_stdio.http import validate_host

    with pytest.raises(ValueError):
        validate_host("0.0.0.0")
    assert validate_host("127.0.0.1") == "127.0.0.1"


def test_stdio_subprocess_lists_compact_tools_without_ida():
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"},
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    process = subprocess.run(
        [sys.executable, "-m", "ida_mcp_stdio"],
        input="\n".join(json.dumps(m) for m in messages) + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    responses = [json.loads(line) for line in process.stdout.splitlines()]
    assert [response["id"] for response in responses] == [1, 2]
    assert len(responses[1]["result"]["tools"]) == 6
