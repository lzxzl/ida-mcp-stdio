"""Private session traces and recoverable, paginated result artifacts."""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse


class SessionStore:
    def __init__(
        self,
        root: Path | None = None,
        inline_limit: int = 65536,
        log_path: Path | None = None,
        agent: str = "unknown",
    ):
        if inline_limit < 16:
            raise ValueError("inline_limit must be at least 16 bytes")
        self.session_id = uuid.uuid4().hex
        self.root = (
            root or Path.home() / ".local" / "state" / "ida-mcp-stdio" / self.session_id
        )
        self.inline_limit = inline_limit
        self.log_path = log_path
        self.agent = agent
        self.artifacts: dict[str, Path] = {}
        self._lock = threading.RLock()

    def _directory(self, path: Path) -> None:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)

    def package(self, value) -> dict:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(encoded) <= self.inline_limit:
            return value
        with self._lock:
            self._directory(self.root)
            key = uuid.uuid4().hex
            path = self.root / (key + ".json")
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(encoded)
            uri = "ida-mcp://artifact/" + key
            self.artifacts[uri] = path
        return {
            "artifact": {"uri": uri, "bytes": len(encoded), "path": str(path)},
            "preview": encoded[:1024].decode("utf-8", errors="ignore"),
            "hint": "Use resources/read. Join page chunks in order to recover the complete JSON result.",
        }

    def list_resources(self) -> list[dict]:
        with self._lock:
            return [
                {"uri": uri, "name": path.name, "mimeType": "application/json"}
                for uri, path in self.artifacts.items()
            ]

    def read_resource(self, uri: str) -> dict:
        parsed = urlparse(uri)
        base = parsed._replace(query="", fragment="").geturl()
        with self._lock:
            path = self.artifacts.get(base)
        if path is None or parsed.fragment:
            raise ValueError("Unknown result artifact URI for this session")
        arguments = parse_qs(parsed.query)
        offset = int(arguments.get("offset", ["0"])[0])
        limit = int(arguments.get("limit", ["16384"])[0])
        if offset < 0 or not 4 <= limit <= 65536:
            raise ValueError("offset must be >=0 and limit between 4 and 65536 bytes")
        size = path.stat().st_size
        if offset > size:
            raise ValueError("offset exceeds artifact size")
        with path.open("rb") as source:
            source.seek(offset)
            chunk = source.read(limit)
        if chunk and 0x80 <= chunk[0] <= 0xBF:
            raise ValueError("offset must fall on a UTF-8 character boundary")
        text = chunk.decode("utf-8", errors="ignore")
        next_offset = offset + len(text.encode("utf-8"))
        next_uri = (
            base + "?" + urlencode({"offset": next_offset})
            if next_offset < size
            else None
        )
        page = {
            "chunk": text,
            "offset": offset,
            "next_offset": next_offset if next_uri else None,
            "next_uri": next_uri,
            "bytes": size,
        }
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(page, ensure_ascii=False),
                }
            ]
        }

    def record(self, event: str, **fields) -> None:
        if self.log_path is None:
            return
        record = {
            "session_id": self.session_id,
            "agent": self.agent,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        try:
            with self._lock:
                self._directory(self.log_path.parent)
                descriptor = os.open(
                    self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
                )
                with os.fdopen(descriptor, "a", encoding="utf-8") as output:
                    os.chmod(self.log_path, 0o600)
                    output.write(
                        json.dumps(record, ensure_ascii=False, default=str) + "\n"
                    )
        except (OSError, ValueError, TypeError) as error:
            logging.getLogger("ida-mcp-stdio").warning(
                "Session trace unavailable (%s): %s", self.log_path, error
            )
