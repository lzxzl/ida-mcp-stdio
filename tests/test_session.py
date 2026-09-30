from __future__ import annotations

import json

import pytest

from ida_mcp_stdio import session


def test_large_unicode_result_can_be_reassembled(tmp_path):
    store = session.SessionStore(root=tmp_path, inline_limit=32)
    value = {"text": "界" * 100}
    packaged = store.package(value)
    assert packaged["artifact"]["bytes"] > 300
    uri = packaged["artifact"]["uri"]
    chunks = []
    while uri:
        resource = store.read_resource(uri + ("&" if "?" in uri else "?") + "limit=32")
        page = json.loads(resource["contents"][0]["text"])
        chunks.append(page["chunk"])
        uri = page["next_uri"]
    assert json.loads("".join(chunks)) == value


def test_resource_uri_cannot_read_arbitrary_files(tmp_path):
    store = session.SessionStore(root=tmp_path)
    for uri in (
        "file:///etc/passwd",
        "ida-mcp://artifact/../../etc/passwd",
        "ida-mcp://artifact/unknown",
    ):
        with pytest.raises(ValueError):
            store.read_resource(uri)


def test_session_log_records_valid_jsonl_with_private_permissions(tmp_path):
    log = tmp_path / "trace.jsonl"
    store = session.SessionStore(
        root=tmp_path / "artifacts", log_path=log, agent="codex"
    )
    store.record("tool_end", request_id=1, duration=0.2, output={"ok": True})
    event = json.loads(log.read_text())
    assert event["agent"] == "codex"
    assert event["event"] == "tool_end"
    assert event["output"] == {"ok": True}
    assert log.stat().st_mode & 0o777 == 0o600


def test_unwritable_trace_does_not_fail_completed_tool(tmp_path):
    # A directory cannot be appended as JSONL, even under an unrestricted account.
    store = session.SessionStore(root=tmp_path / "artifacts", log_path=tmp_path)
    store.record("tool_end", output={"modified": True})
