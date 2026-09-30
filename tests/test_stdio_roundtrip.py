"""Real Python client/stdio protocol checks without an IDA license."""

from __future__ import annotations

from ida_mcp_stdio import IDAMCPClient


def test_client_reads_complete_paginated_artifact():
    with IDAMCPClient(
        tool_profile="compact", server_args=["--inline-limit", "64"]
    ) as client:
        assert client.initialize()["protocolVersion"] == "2025-11-25"
        assert len(client.list_tools()) == 6
        result = client.reference("decompile")
        assert result["entries"]
        assert "artifact" not in result
