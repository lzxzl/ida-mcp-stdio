"""Database owners, isolated worker transport and optional official Nexus adapter."""

from __future__ import annotations

import json
import logging
import math
import os
import queue
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger("ida-mcp-stdio")


def _timeout(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError("timeout must be a positive finite number")
    return float(value)


class Worker:
    """One process owns one IDB; requests are serialized per process."""

    def __init__(self, command: list[str]):
        environment = os.environ.copy()
        source_root = str(Path(__file__).resolve().parent.parent)
        environment["PYTHONPATH"] = os.pathsep.join(
            filter(None, (source_root, environment.get("PYTHONPATH", "")))
        )
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=environment,
        )
        self.responses: queue.Queue = queue.Queue()
        self.lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._pending_operations: set[str] = set()
        self._cancelled_operations: set[str] = set()
        self.sequence = 0
        self.active_operation: str | None = None
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._stderr = threading.Thread(target=self._read_stderr, daemon=True)
        self._reader.start()
        self._stderr.start()

    @property
    def connected(self) -> bool:
        return self.process.poll() is None

    def _read(self) -> None:
        try:
            for line in self.process.stdout:
                self.responses.put(json.loads(line))
        except (OSError, ValueError) as error:
            self.responses.put(error)
        finally:
            self.responses.put(None)

    def _read_stderr(self) -> None:
        try:
            for line in self.process.stderr:
                logger.debug("worker[%s]: %s", self.process.pid, line.rstrip())
        except (OSError, ValueError):
            pass

    def request(
        self,
        action: str,
        timeout: float = 360,
        operation_id: str | None = None,
        cancel_event: threading.Event | None = None,
        **arguments,
    ) -> Any:
        timeout = _timeout(timeout)
        with self._state_lock:
            if operation_id:
                self._pending_operations.add(operation_id)
        try:
            return self._request_locked(
                action, timeout, operation_id, cancel_event, arguments
            )
        finally:
            with self._state_lock:
                self._pending_operations.discard(operation_id)
                self._cancelled_operations.discard(operation_id)

    def _request_locked(self, action, timeout, operation_id, cancel_event, arguments):
        with self.lock:
            with self._state_lock:
                if operation_id in self._cancelled_operations or (
                    cancel_event and cancel_event.is_set()
                ):
                    raise RuntimeError(
                        "Operation cancelled before execution; database remains available"
                    )
                if not self.connected:
                    raise RuntimeError(
                        "Database worker disconnected. Reopen the database; the last operation may have partially completed."
                    )
                self.active_operation = operation_id
            self.sequence += 1
            request_id = self.sequence
            try:
                self.process.stdin.write(
                    json.dumps(
                        {"id": request_id, "action": action, **arguments},
                        allow_nan=False,
                    )
                    + "\n"
                )
                self.process.stdin.flush()
                response = self.responses.get(timeout=timeout)
                if not isinstance(response, dict) or response.get("id") != request_id:
                    self.terminate()
                    raise RuntimeError(
                        "Database worker crashed or returned invalid data. Reopen the database; changes may be incomplete."
                    )
                if "error" in response:
                    raise RuntimeError(response["error"])
                return response["result"]
            except queue.Empty as error:
                self.terminate()
                raise TimeoutError(
                    f"IDA operation timed out after {timeout:g}s. Worker terminated; unsaved changes may be lost. Reopen this database before continuing."
                ) from error
            except (BrokenPipeError, OSError) as error:
                self.terminate()
                raise RuntimeError(
                    "Database worker disconnected; reopen this database"
                ) from error
            finally:
                with self._state_lock:
                    self.active_operation = None

    def cancel(self, operation_id: str) -> bool:
        with self._state_lock:
            if operation_id not in self._pending_operations:
                return False
            self._cancelled_operations.add(operation_id)
            if self.active_operation == operation_id:
                # Hold the state lock until termination completes. A finished
                # request cannot hand this owner to another operation meanwhile.
                self.terminate()
            return True

    def terminate(self) -> None:
        if self.connected:
            self.process.kill()
        self.process.wait(timeout=5)

    def dispose(self) -> None:
        self.terminate()
        self._reader.join(timeout=1)
        self._stderr.join(timeout=1)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


class LocalBackend:
    """Multi-IDB idalib backend compatible with IDA 9.0+, without GUI sharing."""

    def __init__(self, max_workers: int = 4, worker_command: list[str] | None = None):
        if (
            not isinstance(max_workers, int)
            or isinstance(max_workers, bool)
            or max_workers < 1
        ):
            raise ValueError("max_workers must be a positive integer")
        self.max_workers = max_workers
        self.worker_command = worker_command or [
            sys.executable,
            "-m",
            "ida_mcp_stdio.worker",
        ]
        self.instances: dict[str, tuple[Path, Worker]] = {}
        self.current_instance_id: str | None = None
        self._lock = threading.RLock()
        self._closed = False

    def resolve_instance_id(self, instance_id: str | None) -> str:
        target = instance_id or self.current_instance_id
        if not target or target not in self.instances:
            raise ValueError(
                "No database selected. Use open_database first or pass a valid instance_id."
            )
        return target

    def _worker(self, instance_id: str | None) -> Worker:
        return self.instances[self.resolve_instance_id(instance_id)][1]

    def open_database(
        self, path: str, set_current: bool = True, force_reanalyze: bool = False
    ) -> dict:
        binary = Path(path).expanduser().resolve()
        if force_reanalyze and binary.suffix.lower() in {
            ".i64",
            ".idb",
            ".id0",
            ".id1",
            ".id2",
            ".nam",
            ".til",
        }:
            raise ValueError(
                "force_reanalyze requires the original input binary, not an IDB or database component"
            )
        if not binary.is_file():
            raise ValueError(f"Binary not found or not a file: {binary}")
        with self._lock:
            if self._closed:
                raise RuntimeError(
                    "Database manager has shut down; create a new manager"
                )
            for target, (existing, worker) in list(self.instances.items()):
                if existing == binary:
                    if worker.connected:
                        if force_reanalyze:
                            raise ValueError(
                                "Close this database before requesting force_reanalyze"
                            )
                        if set_current:
                            self.current_instance_id = target
                        return {
                            "success": True,
                            "path": str(binary),
                            "instance_id": target,
                            "backend": "idalib",
                            "status": "ready",
                            "reused": True,
                            "existing_db": True,
                        }
                    worker.dispose()
                    del self.instances[target]
            if (
                sum(worker.connected for _, worker in self.instances.values())
                >= self.max_workers
            ):
                raise RuntimeError(
                    f"Worker limit ({self.max_workers}) reached. Close an unused database first."
                )
            worker = Worker(self.worker_command)
            try:
                opened = worker.request(
                    "open", path=str(binary), force_reanalyze=force_reanalyze
                )
                if not opened.get("success"):
                    raise RuntimeError(
                        opened.get("error", "IDA could not open the database")
                    )
            except BaseException:
                worker.dispose()
                raise
            target = uuid.uuid4().hex
            self.instances[target] = binary, worker
            if set_current:
                self.current_instance_id = target
            return {
                **opened,
                "instance_id": target,
                "backend": "idalib",
                "status": "ready",
                "reused": False,
                "hint": "Use reference to check APIs, then execute_python; tools contains existing analysis helpers.",
            }

    def list_databases(self) -> dict:
        with self._lock:
            return {
                "instances": [
                    {
                        "instance_id": target,
                        "path": str(path),
                        "backend": "idalib",
                        "status": "ready" if worker.connected else "disconnected",
                        "current": target == self.current_instance_id,
                    }
                    for target, (path, worker) in self.instances.items()
                ]
            }

    def execute_python(
        self,
        code: str,
        instance_id: str | None,
        timeout: float = 360,
        persist_globals: bool = True,
        operation_id: str | None = None,
        cancel_event: threading.Event | None = None,
    ) -> dict:
        return self._worker(instance_id).request(
            "execute",
            timeout=timeout,
            operation_id=operation_id,
            cancel_event=cancel_event,
            code=code,
            persist_globals=persist_globals,
        )

    def execute_tool(
        self,
        name: str,
        arguments: dict,
        instance_id: str | None = None,
        operation_id: str | None = None,
        cancel_event: threading.Event | None = None,
    ) -> Any:
        return self._worker(instance_id).request(
            "tool",
            name=name,
            arguments=arguments,
            operation_id=operation_id,
            cancel_event=cancel_event,
        )

    def save_database(self, instance_id: str | None) -> dict:
        return self._worker(instance_id).request("save")

    def close_database(self, instance_id: str | None, save: bool = True) -> dict:
        with self._lock:
            target = self.resolve_instance_id(instance_id)
            path, worker = self.instances[target]
            result = (
                worker.request("close", save=save)
                if worker.connected
                else {
                    "success": True,
                    "saved": False,
                    "warning": "Worker was disconnected; unsaved changes could not be saved.",
                }
            )
            if not result.get("success"):
                raise RuntimeError(
                    result.get("error", "IDA failed to close the database")
                )
            worker.dispose()
            del self.instances[target]
            if self.current_instance_id == target:
                self.current_instance_id = next(
                    (
                        key
                        for key, (_, value) in self.instances.items()
                        if value.connected
                    ),
                    None,
                )
            return {**result, "closed": str(path), "instance_id": target}

    def cancel_operation(self, instance_id: str, operation_id: str) -> bool:
        return self._worker(instance_id).cancel(operation_id)

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            for target, (_, worker) in list(self.instances.items()):
                try:
                    self.close_database(target)
                except Exception:
                    logger.exception(
                        "Could not save/close worker %s during shutdown", target
                    )
                    worker.dispose()
                    self.instances.pop(target, None)
            self.current_instance_id = None


class NexusBackend:
    """Adapt the official public Manager API; IDA 9.4+ and Python 3.11+ required."""

    def __init__(self):
        try:
            from ida_nexus import DatabaseManager
        except ImportError as error:
            raise RuntimeError(
                "Nexus backend requires Python >=3.11, IDA >=9.4 and pip install 'ida-mcp-stdio[nexus]'"
            ) from error
        from .nexus_compat import install_nexus_compatibility

        install_nexus_compatibility()
        self.manager = DatabaseManager()

    def resolve_instance_id(self, instance_id: str | None) -> str:
        return self.manager.resolve_instance_id(instance_id)

    def open_database(
        self, path: str, set_current: bool = True, force_reanalyze: bool = False
    ) -> dict:
        if force_reanalyze:
            raise ValueError(
                "Nexus cannot force-rebuild a shared database; use the native backend for this operation"
            )
        return {
            "success": True,
            "path": str(Path(path).expanduser().resolve()),
            **self.manager.open_database(path, set_current=set_current),
        }

    def list_databases(self) -> dict:
        return self.manager.list_databases()

    def _tools_prefix(self) -> str:
        source_root = str(Path(__file__).resolve().parent.parent)
        return (
            f"import sys as _mcp_sys\n_mcp_sys.path.insert(0, {source_root!r}) if {source_root!r} not in _mcp_sys.path else None\n"
            "from ida_mcp_stdio.server import _import_tools as _mcp_import_tools, RUNTIME_TOOLS as _mcp_controls\n_mcp_import_tools()\n"
            "from ida_mcp_stdio.tools import get_registry as _mcp_registry\n"
            "from types import SimpleNamespace as _mcp_namespace\n"
            "tools = _mcp_namespace(**{t.name: t.func for t in _mcp_registry().list_tools() if t.name not in _mcp_controls})\n"
            "from ida_mcp_stdio.tools.database import current_database_info as _mcp_database_info\n"
            "tools.get_current_database = _mcp_database_info\n"
        )

    def execute_python(
        self,
        code: str,
        instance_id: str | None,
        timeout: float = 360,
        persist_globals: bool = True,
        operation_id: str | None = None,
        cancel_event: threading.Event | None = None,
    ) -> dict:
        target = self.resolve_instance_id(instance_id)
        if cancel_event and cancel_event.is_set():
            raise RuntimeError("Operation cancelled before execution")
        self.manager.ensure_autoanalysis(target, operation_id=operation_id)
        if cancel_event and cancel_event.is_set():
            raise RuntimeError("Operation cancelled before execution")
        code = f"__import__('ida_mcp_stdio.execution', fromlist=['execute_code']).execute_code({code!r}, globals(), {persist_globals!r})"
        response = self.manager.execute_python(
            self._tools_prefix() + code,
            target,
            timeout=_timeout(timeout),
            persist_globals=True,
            operation_id=operation_id,
        )
        return response["result"]

    def execute_tool(
        self,
        name: str,
        arguments: dict,
        instance_id: str | None = None,
        operation_id: str | None = None,
        cancel_event: threading.Event | None = None,
    ) -> Any:
        result = self.execute_python(
            (
                "tools.get_current_database()"
                if name == "get_current_database"
                else f"_mcp_registry().call_tool({name!r}, {arguments!r})"
            ),
            instance_id,
            operation_id=operation_id,
            cancel_event=cancel_event,
        )
        if result.get("error"):
            raise RuntimeError(result["error"])
        return result["result"]

    def save_database(self, instance_id: str | None) -> dict:
        return self.manager.save_database(instance_id)

    def close_database(self, instance_id: str | None, save: bool = True) -> dict:
        if not save:
            raise ValueError(
                "Nexus shares the IDB; discard-on-close is only supported by the native backend"
            )
        target = self.resolve_instance_id(instance_id)
        self.manager.save_database(target)
        return {"success": True, **self.manager.close_database(target)}

    def cancel_operation(self, instance_id: str, operation_id: str) -> bool:
        return self.manager.cancel_operation(instance_id, operation_id)

    def shutdown(self) -> None:
        self.manager.shutdown()
