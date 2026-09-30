"""Exercise the optional transport with real HTTP and the official SDK client."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import time

import pytest

pytest.importorskip("mcp")
pytest.importorskip("uvicorn")


def test_http_sdk_roundtrip_and_session_artifact_isolation(tmp_path):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    log_path = tmp_path / "http.log"
    with log_path.open("w") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "ida_mcp_stdio",
                "--transport",
                "http",
                "--port",
                str(port),
                "--inline-limit",
                "64",
            ],
            stdout=subprocess.DEVNULL,
            stderr=log,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    pytest.fail(log_path.read_text())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        pytest.fail(
                            "HTTP server did not start: " + log_path.read_text()
                        )
                    time.sleep(0.05)

            async def exercise():
                url = f"http://127.0.0.1:{port}/mcp/"
                async with (
                    streamable_http_client(url) as first_streams,
                    ClientSession(first_streams[0], first_streams[1]) as first,
                ):
                    await first.initialize()
                    assert len((await first.list_tools()).tools) == 6
                    result = await first.call_tool("reference", {"query": "decompile"})
                    assert result.isError is False
                    artifact = result.structuredContent["artifact"]["uri"]
                    page = await first.read_resource(artifact)
                    assert json.loads(page.contents[0].text)["chunk"]
                    assert len((await first.list_resources()).resources) == 1
                    async with (
                        streamable_http_client(url) as second_streams,
                        ClientSession(second_streams[0], second_streams[1]) as second,
                    ):
                        await second.initialize()
                        assert (await second.list_resources()).resources == []

            asyncio.run(exercise())
        finally:
            process.terminate()
            process.wait(timeout=10)
