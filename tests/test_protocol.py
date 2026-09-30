from __future__ import annotations

import io
import json

import pytest

from ida_mcp_stdio.server import StdioMCPServer, _import_tools
from ida_mcp_stdio.tools import ToolsRegistry


@pytest.fixture
def server(tmp_path):
    _import_tools()
    instance = StdioMCPServer(session_dir=tmp_path)
    yield instance
    instance._shutdown()


def request(method, params=None, request_id=1):
    return {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": request_id,
    }


def test_compact_discovery_and_legacy_profiles(server):
    tools = server.handle_request(request("tools/list"))["result"]["tools"]
    assert {tool["name"] for tool in tools} == {
        "open_database",
        "close_database",
        "list_databases",
        "save_database",
        "execute_python",
        "reference",
    }
    server.tool_profile = "legacy"
    names = {
        tool["name"]
        for tool in server.handle_request(request("tools/list"))["result"]["tools"]
    }
    assert "decompile" in names
    assert "extract_function_facts" in names
    assert "execute_python" not in names


def test_reference_does_not_load_ida(server):
    result = server.handle_request(
        request(
            "tools/call", {"name": "reference", "arguments": {"query": "decompile"}}
        )
    )
    assert result["result"]["isError"] is False
    assert result["result"]["structuredContent"]["entries"]
    assert server._idapro_imported is False


def test_notifications_never_produce_responses(server):
    assert server.handle_request({"jsonrpc": "2.0", "method": "unknown"}) is None
    assert server.handle_request({"jsonrpc": "2.0", "method": "ping"}) is None


def test_invalid_jsonrpc_and_null_params(server):
    assert (
        server.handle_request({"jsonrpc": "1.0", "method": "ping", "id": 1})["error"][
            "code"
        ]
        == -32600
    )
    assert (
        server.handle_request(
            {"jsonrpc": "2.0", "method": "initialize", "params": None, "id": 1}
        )["error"]["code"]
        == -32602
    )


def test_supported_protocol_negotiation(server):
    response = server.handle_request(
        request("initialize", {"protocolVersion": "2025-11-25"})
    )
    assert response["result"]["protocolVersion"] == "2025-11-25"
    assert response["result"]["capabilities"]["resources"] == {}
    assert response["result"]["instructions"]


def test_invalid_parameters_and_internal_typeerror_differ(server):
    registry = ToolsRegistry()

    def reference(count: int):
        raise TypeError("internal failure")

    registry.register(reference)
    server.registry = registry
    bad = server.handle_request(
        request("tools/call", {"name": "reference", "arguments": {"count": True}})
    )
    assert bad["error"]["code"] == -32602
    internal = server.handle_request(
        request("tools/call", {"name": "reference", "arguments": {"count": 1}})
    )
    assert internal["result"]["isError"] is True
    assert "internal failure" in internal["result"]["content"][0]["text"]


def test_shutdown_saves_and_releases_backend_once(server):
    class Backend:
        calls = 0

        def shutdown(self):
            self.calls += 1

    backend = Backend()
    server.manager = backend
    server._shutdown()
    server._shutdown()
    assert backend.calls == 1


def test_unwritable_trace_does_not_turn_valid_result_into_failure(server, tmp_path):
    server.session.log_path = tmp_path
    response = server.handle_request(
        request(
            "tools/call", {"name": "reference", "arguments": {"query": "decompile"}}
        )
    )
    assert response["result"]["isError"] is False


def test_queued_stdio_cancel_prevents_tool_side_effect(server, monkeypatch):
    effects = []
    registry = ToolsRegistry()

    def reference():
        effects.append("executed")
        return {"ok": True}

    registry.register(reference)
    server.registry = registry
    messages = [
        request("tools/call", {"name": "reference"}, 2),
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 2},
        },
    ]
    monkeypatch.setattr(
        "sys.stdin", io.StringIO("\n".join(json.dumps(m) for m in messages) + "\n")
    )
    output = io.StringIO()
    monkeypatch.setattr("sys.stdout", output)
    server.run()
    assert effects == []
    assert json.loads(output.getvalue())["result"]["isError"] is True


def test_invalid_protocol_notification_cannot_cancel_worker(server):
    class Backend:
        calls = 0

        def cancel_operation(self, *args):
            self.calls += 1

        def shutdown(self):
            pass

    backend = Backend()
    server.manager = backend
    server._active_operations[2] = ("db", "operation")
    server.handle_request(
        {
            "jsonrpc": "1.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 2},
        }
    )
    assert backend.calls == 0
