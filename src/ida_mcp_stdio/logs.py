"""Private ZIP exports of selected MCP traces and explicitly linked files."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .transcripts import (
    iter_transcript_references,
    read_records,
    resolve_reference,
    session_files,
    skipped_records,
)

MANIFEST_NAME = "ida-mcp-logs.json"


def _artifact_references(
    records: list[dict], semantic_path: Path
) -> tuple[list[str], list[str]]:
    """Use server packaging provenance, with a constrained legacy fallback.

    Arguments, transcript metadata and nested analysis data never authorize file
    inclusion. A present null result_artifact explicitly means an inline result.
    Older traces must contain the exact package envelope and session/key path.
    """
    paths, warnings = [], []
    session_id = None
    for record in records:
        identity = record.get("session_id")
        if isinstance(identity, str) and identity:
            session_id = identity
        if record.get("event") not in ("tool_end", "tool_result"):
            continue
        output = record.get("output")
        if not isinstance(output, dict):
            continue
        legacy = "result_artifact" not in record
        descriptor = output.get("artifact") if legacy else record["result_artifact"]
        if not isinstance(descriptor, dict):
            continue
        if legacy and (
            set(output) != {"artifact", "preview", "hint"}
            or not isinstance(output["preview"], str)
            or output["hint"]
            != "Use resources/read. Join page chunks in order to recover the complete JSON result."
        ):
            continue
        if not legacy and output.get("artifact") != descriptor:
            warnings.append(
                "Skipped artifact descriptor that does not match the packaged result"
            )
            continue
        uri, recorded, size = (
            descriptor.get("uri"),
            descriptor.get("path"),
            descriptor.get("bytes"),
        )
        match = (
            re.fullmatch(r"ida-mcp://artifact/([0-9a-f]{32})", uri)
            if isinstance(uri, str)
            else None
        )
        if (
            match is None
            or not isinstance(recorded, str)
            or not recorded
            or "\x00" in recorded
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            continue
        try:
            source = resolve_reference(recorded, semantic_path)
        except (ValueError, OSError):
            warnings.append(f"Skipped invalid artifact path: {recorded}")
            continue
        if source.name != match[1] + ".json":
            warnings.append(
                f"Skipped artifact with a path that does not match its URI: {recorded}"
            )
            continue
        if legacy and (not session_id or source.parent.name != session_id):
            warnings.append(
                f"Skipped legacy artifact outside its recorded session directory: {recorded}"
            )
            continue
        paths.append(recorded)
    return list(dict.fromkeys(paths)), warnings


def _member(source: Path, folder: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]", "_", source.name).strip(".")[:120] or "trace"
    digest = hashlib.sha256(str(source).encode("utf-8")).hexdigest()[:16]
    return f"{folder}/{digest}-{name}"


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def _archive_file(archive: zipfile.ZipFile, path: Path, member: str) -> dict:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as source, archive.open(_zip_info(member), "w") as target:
        while chunk := source.read(1024 * 1024):
            target.write(chunk)
            digest.update(chunk)
            size += len(chunk)
    return {
        "source_path": str(path),
        "archive_path": member,
        "size": size,
        "sha256": digest.hexdigest(),
    }


def export_logs(
    state_dir: Path,
    output_path: Path,
    session_paths: list[Path] | None = None,
    include_transcripts: bool = True,
) -> Path:
    """Archive raw selected sessions, referenced artifacts and linked transcripts.

    JSONL bytes are preserved, including truncated trailing records. The manifest
    records missing linked files and skipped records. Discovery excludes unrelated
    JSON/config files. Existing output is refused; callers can choose another name.
    """
    selected = session_paths if session_paths is not None else session_files(state_dir)
    sessions = list(dict.fromkeys(Path(p).expanduser().resolve() for p in selected))
    if not sessions:
        raise ValueError("No MCP session traces found")
    output = output_path.expanduser().resolve()
    if output in sessions:
        raise ValueError("Output cannot overwrite a selected trace")
    if output.exists():
        raise FileExistsError(f"Output already exists: {output}")
    manifest = {
        "format": "ida-mcp-logs",
        "schema": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sessions": [],
        "files": [],
        "path_map": {},
        "warnings": [],
    }
    sources: dict[Path, tuple[str, str]] = {
        path: ("semantic_session", _member(path, "sessions")) for path in sessions
    }
    for path in sessions:
        if not path.is_file():
            raise ValueError(f"Session trace is not a file: {path}")
        records, warnings = read_records(path)
        manifest["warnings"].extend(f"{path}: {w}" for w in warnings)
        member = _member(path, "sessions")
        sources[path] = ("semantic_session", member)
        session = {
            "source_path": str(path),
            "archive_path": member,
            "agent_sessions": [],
            "artifacts": [],
            "warnings": list(warnings),
            "skipped_records": skipped_records(warnings),
        }
        manifest["sessions"].append(session)
        references = (
            list(iter_transcript_references(records)) if include_transcripts else []
        )
        for kind, recorded in references:
            entry = {
                "kind": kind,
                "recorded_path": recorded,
                "source_path": None,
                "archive_path": None,
            }
            session["agent_sessions"].append(entry)
            try:
                source = resolve_reference(recorded, path)
                if source == path or not source.is_file():
                    raise FileNotFoundError(recorded)
                linked_member = _member(source, "agent-sessions")
                sources.setdefault(source, ("agent_session", linked_member))
                entry.update(source_path=str(source), archive_path=sources[source][1])
            except (OSError, ValueError) as exc:
                manifest["warnings"].append(
                    f"Missing linked {kind} transcript {recorded}: {exc}"
                )
        artifacts, artifact_warnings = _artifact_references(records, path)
        manifest["warnings"].extend(
            f"{path}: {warning}" for warning in artifact_warnings
        )
        for recorded in artifacts:
            entry = {
                "recorded_path": recorded,
                "source_path": None,
                "archive_path": None,
            }
            session["artifacts"].append(entry)
            try:
                source = resolve_reference(recorded, path)
                if not source.is_file():
                    raise FileNotFoundError(recorded)
                artifact_member = _member(source, "artifacts")
                sources.setdefault(source, ("artifact", artifact_member))
                entry.update(source_path=str(source), archive_path=sources[source][1])
            except (OSError, ValueError) as exc:
                manifest["warnings"].append(f"Missing artifact {recorded}: {exc}")
    if output in sources:
        raise ValueError("Output cannot overwrite a linked source file")
    output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    temporary = output.parent / f".{output.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with (
            os.fdopen(descriptor, "wb") as destination,
            zipfile.ZipFile(destination, "w") as archive,
        ):
            for source, (kind, member) in sources.items():
                entry = _archive_file(archive, source, member)
                entry["kind"] = kind
                manifest["files"].append(entry)
                manifest["path_map"][str(source)] = member
            archive.writestr(
                _zip_info(MANIFEST_NAME),
                json.dumps(
                    manifest, ensure_ascii=False, indent=2, allow_nan=False
                ).encode("utf-8"),
            )
        # A hard link publishes atomically while refusing a raced existing output.
        os.link(temporary, output)
        output.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return output
