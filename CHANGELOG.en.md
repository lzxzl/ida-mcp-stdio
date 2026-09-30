# Changelog

[中文](CHANGELOG.md)

## 0.3.0

- Separated the stdio server from IDA owners. Each database runs independently, with instance routing, timeouts, and cancellation.
- Added a six-tool compact profile, composable Python execution, persistent contexts, await, and offline API lookup.
- Large results are saved as complete artifacts with paginated retrieval. Added JSONL session recording and HTML export.
- Added the official Nexus backend for IDA 9.4+ headless and shared GUI use. The native backend retains IDA 9.2 support.
- Added optional Streamable HTTP, with separate routing and artifact indexes for each session.
- Extended analysis helpers and structured fact interfaces, with Python client wrappers and local regression tests.
- Fixed the statfs ABI probe for Nexus 0.13.0 on macOS.
