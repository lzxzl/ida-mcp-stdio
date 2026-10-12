# Changelog

[中文](CHANGELOG.md)

## 0.5.0 (unreleased)

- `install` / `update --gui-plugin` deploys the official GUI provider and checks or creates an IDAPython environment. Dry runs never execute HCLI.
- `--hooks` adds an OpenCode V1 active-session plugin and durable ZCode transcripts, preserving unrelated hooks and existing disabled settings.
- Added Codex / Claude Code plugin packages, a shared marketplace catalog and a configurable Python launcher.
- Added wheel / sdist version checks and a PyPI Trusted Publisher workflow. Publishing requires GitHub and PyPI setup.
- Added `benchmark run / compare / usage` with workload/result checks and separate workflow metrics and recorded transcript usage.
- `IDA_MCP_STDIO_STATE_DIR` selects the state directory for traces, artifacts, dashboards and transcripts.
- Raised the Nexus dependency floor to 0.13.4 for the current official GUI plugin. Native IDA 9.2 support remains.

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
