from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

from ida_mcp_stdio import backends


@pytest.fixture
def manager():
    backend = backends.LocalBackend(
        worker_command=[
            sys.executable,
            str(Path(__file__).parent / "fixtures" / "protocol_worker.py"),
        ]
    )
    yield backend
    backend.shutdown()


def test_two_databases_keep_separate_globals(manager, tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.touch()
    second.touch()
    a = manager.open_database(str(first))["instance_id"]
    b = manager.open_database(str(second))["instance_id"]
    manager.execute_python("value = 7", a)
    assert manager.execute_python("value", a)["result"] == 7
    assert manager.execute_python("value", b)["error"]["type"] == "NameError"
    assert len(manager.list_databases()["instances"]) == 2


def test_same_path_reuses_worker(manager, tmp_path):
    binary = tmp_path / "sample"
    binary.touch()
    first = manager.open_database(str(binary))
    second = manager.open_database(str(tmp_path / "." / "sample"))
    assert first["instance_id"] == second["instance_id"]
    assert len(manager.list_databases()["instances"]) == 1


def test_invalid_new_path_preserves_current_target(manager, tmp_path):
    binary = tmp_path / "sample"
    binary.touch()
    opened = manager.open_database(str(binary))
    with pytest.raises(ValueError):
        manager.open_database(str(tmp_path / "missing"))
    assert manager.execute_python("3 + 4", None)["result"] == 7
    assert manager.current_instance_id == opened["instance_id"]


def test_timeout_and_crash_only_invalidate_the_target(manager, tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    first.touch()
    second.touch()
    a = manager.open_database(str(first))["instance_id"]
    b = manager.open_database(str(second))["instance_id"]
    with pytest.raises(TimeoutError):
        manager.execute_python("import time; time.sleep(5)", a, timeout=0.03)
    assert manager.execute_python("42", b)["result"] == 42
    with pytest.raises(RuntimeError):
        manager.execute_python("import os; os._exit(2)", b)
    assert all(
        row["status"] == "disconnected" for row in manager.list_databases()["instances"]
    )


def test_close_failure_keeps_database_visible(manager, tmp_path):
    binary = tmp_path / "close-fail"
    binary.touch()
    target = manager.open_database(str(binary))["instance_id"]
    with pytest.raises(RuntimeError):
        manager.close_database(target)
    assert manager.execute_python("42", target)["result"] == 42


def test_save_does_not_close_the_target(manager, tmp_path):
    binary = tmp_path / "sample"
    binary.touch()
    target = manager.open_database(str(binary))["instance_id"]
    assert manager.save_database(target)["idb_path"].endswith("sample.i64")
    assert manager.execute_python("42", target)["result"] == 42


def test_worker_limit_does_not_evict_open_database(tmp_path):
    backend = backends.LocalBackend(
        max_workers=1,
        worker_command=[
            sys.executable,
            str(Path(__file__).parent / "fixtures" / "protocol_worker.py"),
        ],
    )
    first, second = tmp_path / "first", tmp_path / "second"
    first.touch()
    second.touch()
    try:
        backend.open_database(str(first))
        with pytest.raises(RuntimeError):
            backend.open_database(str(second))
        assert backend.execute_python("42", None)["result"] == 42
    finally:
        backend.shutdown()


def test_nexus_close_pins_target_before_save_changes_selection():
    class Manager:
        current = "A"
        closed = None

        def resolve_instance_id(self, value):
            return value or self.current

        def save_database(self, value):
            self.current = "B"

        def close_database(self, value):
            self.closed = value or self.current
            return {"closed": True}

    backend = object.__new__(backends.NexusBackend)
    backend.manager = Manager()
    backend.close_database(None)
    assert backend.manager.closed == "A"


def test_queued_cancellation_does_not_execute_or_kill_running_operation(
    manager, tmp_path
):
    binary = tmp_path / "sample"
    binary.touch()
    target = manager.open_database(str(binary))["instance_id"]
    worker = manager._worker(target)
    errors = []

    def queued():
        try:
            manager.execute_python("marker = 42", target, operation_id="queued")
        except RuntimeError as error:
            errors.append(str(error))

    with worker.lock:
        thread = threading.Thread(target=queued)
        thread.start()
        time.sleep(0.03)
        assert manager.cancel_operation(target, "queued") is True
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert errors
    assert manager.execute_python('"marker" in globals()', target)["result"] is False


def test_public_initialize_uses_worker_without_importing_ida_in_parent(
    manager, tmp_path, monkeypatch
):
    from ida_mcp_stdio.server import StdioMCPServer

    binary = tmp_path / "sample"
    binary.touch()
    server = StdioMCPServer(binary)
    server.manager = manager
    monkeypatch.setattr(server, "_import_idapro", lambda: False)
    try:
        assert server.initialize_ida() is True
        assert manager.execute_python("42", None)["result"] == 42
        assert server._idapro_imported is False
    finally:
        server._shutdown()


def test_force_reanalysis_of_idb_is_rejected_without_deleting_it(manager, tmp_path):
    database = tmp_path / "valuable.i64"
    database.write_bytes(b"existing database")
    with pytest.raises(ValueError):
        manager.open_database(str(database), force_reanalyze=True)
    assert database.read_bytes() == b"existing database"


def test_shutdown_is_terminal_and_cannot_leak_new_workers(manager, tmp_path):
    binary = tmp_path / "sample"
    binary.touch()
    manager.shutdown()
    with pytest.raises(RuntimeError):
        manager.open_database(str(binary))
