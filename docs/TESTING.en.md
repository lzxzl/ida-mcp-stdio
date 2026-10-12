# Tests and validation scope

[中文](TESTING.md)

## Automated tests

The test directory remains local and is excluded from Git. These commands are for development environments that already have the local tests.

```sh
.venv/bin/python -m pip install -e '.[dev,nexus,http]'
.venv/bin/python -m pytest tests -q

# Enable real IDA tests; macOS example
IDADIR='/Applications/IDA Professional 9.4.app/Contents/MacOS' \
AI4BA_IDA_MCP_TESTS=1 .venv/bin/python -m pytest tests -v

# Coverage
.venv/bin/python -m pytest tests --cov=ida_mcp_stdio --cov-report=term-missing
```

Tests that do not need IDA cover the protocol, argument validation, code execution, database routing, cancellation, artifact pagination, session isolation, the client, and mock analysis helpers. Real IDA cases require an IDA license, a decompiler, and clang. Samples are generated in temporary directories.

`test_backend_real_ida.py` uses macOS installation paths to check native 9.2, native 9.4, and Nexus 9.4. `IDADIR` selects the version used by the real structured fact tests. Cases are skipped when the required environment is missing.

## Validated environment

### 0.5, 2026-10-11 / 12

This run used macOS and Python 3.14, with read-only user configuration / IDA plugin directories and restricted local port binding.

- Full local suite: 414 passed, 7 skipped, 4 failed. All four failures are HTTP / live dashboard localhost binds denied by the environment. Seven IDA cases were skipped because their opt-in flag was unset.
- Native 9.2 / 9.4 database opening, execution, persistent contexts, saving and closing passed. Both versions passed two structured-fact roundtrips with symbol-rich and partially stripped C++ inputs.
- Batch / separate runs of the fixed C sample returned matching facts on both IDA versions, with 1 / 3 workflow requests. No model inference usage benchmark was run.
- All 42 GUI adapter cases passed. Actual HCLI 0.26.2 doctor checks passed, but the isolated directory could not confirm embedded Python. New GUI provider deployment was not verified.
- The actual OpenCode 1.15.13 / SDK 1.14.40 V1 client contract was checked with injected fetch. ZCode 3.14.5 hooks and transient transcripts were inspected in the installed runtime, with persistence, concurrency and configuration tests passing. No new model session was run.
- Claude 2.1.267 strict plugin validation, isolated Codex marketplace installation and actual plugin stdio handshakes passed. Wheel / sdist builds and offline installation passed. Twine, external publication and user-level configuration writes were constrained by the environment.

Native verification used a temporary `IDAUSR`, preserving the user's existing license acceptance state, and temporary artifact / trace storage. The new Nexus extra floor is 0.13.4; the installed library is 0.13.0. The older sharing checks below are not evidence for a new 0.13.4 runtime. Windows, Linux and other IDA products remain unverified on real installations.

### 0.4, 2026-09-30

2026-09-30: macOS, Python 3.14.2, IDA Professional 9.2 / 9.4, ida-nexus 0.13.0, ida-domain 0.5.1, and MCP SDK 1.26.0.

| Pre-release check | Result |
| --- | --- |
| Full pytest with real IDA enabled, IDADIR=9.2 | 293 passed, no skips |
| Full pytest with real IDA enabled, IDADIR=9.4 | 293 passed, no skips |
| Black, Ruff, and Git whitespace checks | Passed |
| Wheel build and stdio handshake / reference without site-packages | Passed |
| All six examples on a real installation | Exited successfully |

- Both IDA versions passed headless open, execution, native stdout isolation, persistent and temporary contexts, await, save, and close checks.
- C++ samples with symbols and partial stripping passed the structured fact roundtrips.
- In the IDA 9.4 GUI, two independent MCP clients shared an owner and executed code on the main thread. Renaming and comment synchronization, decompilation, saving, and lease release passed; the official DatabaseHandle also received IDB events.
- Reopening after a Nexus headless worker exited unexpectedly recovered the saved checkpoint.
- Configuration commands for Codex, Claude Code / Desktop, OpenCode, and ZCode passed real MCP SDK handshakes and tool calls. Claude Code, OpenCode, and ZCode also reported connected themselves.

- Domain 0.5.1 reference coverage matches the official index's 1,621 public API names and includes all 33 complete examples without importing IDA.
- Real Nexus headless tests cover idle release, another client's surviving lease, final checkpoint save and immediate reopen. The GUI remains alive after lease expiry and release.
- HTTP logging/metadata isolation and disconnect delivery before the first application request passed with the real SDK transport and an injected lifecycle event.
- Chrome checks cover live search/filter/refresh and offline HTML. ZIP tests reject artifact-shaped metadata and retain raw malformed traces; invalid/overflowing usage becomes unavailable with warnings.
- Client installer tests cover all five formats, backups, project overrides, custom flags/timeouts, unsupported launchers and private venv updates. A real temporary venv installation/update passed.

pytest coverage measures only processes instrumented with coverage. It cannot establish coverage for independent workers or the GUI. Future IDA versions, real network filesystems, remote multi-user deployments, and all combinations of abnormal exits have not been tested.
