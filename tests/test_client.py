from __future__ import annotations

import io
import subprocess
import threading
import time

import pytest

from ida_mcp_stdio.client import IDAMCPClient, MCPToolError


class _BlockingStdout:
    def __init__(self):
        self.read_calls = 0
        self.read_started = threading.Event()
        self._released = threading.Event()
        self._closed = False

    def readline(self) -> str:
        self.read_calls += 1
        self.read_started.set()
        self._released.wait()
        return ""

    def close(self) -> None:
        self._closed = True
        self._released.set()


class _ScriptedStdout:
    def __init__(self, lines: list[str]):
        self._lines = list(lines)

    def readline(self) -> str:
        if self._lines:
            return self._lines.pop(0)
        return ""

    def close(self) -> None:
        return None


class _FakeStdin:
    def __init__(self):
        self.writes: list[str] = []
        self.closed = False

    def write(self, data: str) -> None:
        self.writes.append(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeProcess:
    def __init__(self, stdout):
        self.stdin = _FakeStdin()
        self.stdout = stdout
        self.stderr = io.StringIO()
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        self.stdout.close()
        return 0

    def kill(self):
        self.returncode = -9
        self.stdout.close()


def test_read_timeout_reuses_single_reader_thread(monkeypatch):
    stdout = _BlockingStdout()
    process = _FakeProcess(stdout)

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)

    client = IDAMCPClient()
    try:
        assert client._stdout_reader_thread is not None
        assert stdout.read_started.wait(timeout=0.5)

        first_thread = client._stdout_reader_thread

        with pytest.raises(TimeoutError):
            client._read_with_timeout(0.01)
        with pytest.raises(TimeoutError):
            client._read_with_timeout(0.01)

        time.sleep(0.02)
        assert client._stdout_reader_thread is first_thread
        assert stdout.read_calls == 1
    finally:
        client.close()


def test_send_request_uses_background_reader_and_skips_noise(monkeypatch):
    stdout = _ScriptedStdout(
        [
            "IDA plugin startup message\n",
            '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n',
        ]
    )
    process = _FakeProcess(stdout)

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)

    client = IDAMCPClient()
    try:
        result = client._send_request("ping")
        assert result == {"ok": True}
        assert process.stdin.writes
    finally:
        client.close()


def test_client_forwards_custom_command_and_env_to_popen(monkeypatch):
    stdout = _BlockingStdout()
    process = _FakeProcess(stdout)
    popen_kwargs = {}
    popen_cmd = []

    def _fake_popen(cmd, **kwargs):
        popen_cmd.extend(cmd)
        popen_kwargs.update(kwargs)
        return process

    monkeypatch.setattr(subprocess, "Popen", _fake_popen)

    client = IDAMCPClient(
        server_command="/custom/python",
        server_args=["-m", "ida_mcp_stdio"],
        process_env={"IDADIR": "/opt/ida", "TVHEADLESS": "1"},
    )
    try:
        assert popen_cmd == ["/custom/python", "-m", "ida_mcp_stdio"]
        assert popen_kwargs["env"]["IDADIR"] == "/opt/ida"
        assert popen_kwargs["env"]["TVHEADLESS"] == "1"
    finally:
        client.close()


def test_send_request_ignores_notifications_and_late_responses(monkeypatch):
    stdout = _ScriptedStdout(
        [
            '{"jsonrpc":"2.0","method":"notifications/message","params":{}}\n',
            '{"jsonrpc":"2.0","id":0,"result":{"wrong":true}}\n',
            '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n',
        ]
    )
    process = _FakeProcess(stdout)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    client = IDAMCPClient()
    try:
        assert client._send_request("ping") == {"ok": True}
    finally:
        client.close()


def test_structured_error_is_raised_even_without_text_content(monkeypatch):
    stdout = _ScriptedStdout(
        [
            '{"jsonrpc":"2.0","id":1,"result":{"isError":true,"structuredContent":{"error":"failed"},"content":[]}}\n'
        ]
    )
    process = _FakeProcess(stdout)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    client = IDAMCPClient()
    try:
        with pytest.raises(MCPToolError):
            client.call_tool("execute_python", {"code": "1"})
    finally:
        client.close()
