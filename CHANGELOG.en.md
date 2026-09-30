# Changelog

[中文](CHANGELOG.md)

## 0.4.0

- Complete offline Domain lookup with modules, decorators, inheritance, installed version, separate examples and full source.
- Add Nexus `--idle-timeout` to release this session's idle headless leases; handle reopening while the last owner finishes saving.
- Record Nexus lifecycle events and send disconnect warnings through MCP logging; expose notifications in the Python client.
- Add a local multi-session dashboard, transcript links, recorded token/cost totals, and ZIP exports of traces, artifacts and linked transcripts.
- Add `install` / `update` with configuration backups for Codex, Claude Code / Desktop, OpenCode and ZCode; support private virtual environments, previews and hooks.
- Keep existing startup commands and add `stdio`, `http`, `dashboard`, `logs` and `hook` subcommands.
- Add an equivalent legacy / compact workflow comparison with request counts, timings, payload bytes and optional tokenizer counts.

## 0.3.0

- Separated the stdio server from IDA owners. Each database runs independently, with instance routing, timeouts, and cancellation.
- Added a six-tool compact profile, composable Python execution, persistent contexts, await, and offline API lookup.
- Large results are saved as complete artifacts with paginated retrieval. Added JSONL session recording and HTML export.
- Added the official Nexus backend for IDA 9.4+ headless and shared GUI use. The native backend retains IDA 9.2 support.
- Added optional Streamable HTTP, with separate routing and artifact indexes for each session.
- Extended analysis helpers and structured fact interfaces, with Python client wrappers and local regression tests.
- Fixed the statfs ABI probe for Nexus 0.13.0 on macOS.
