# Development state

This document summarizes the portable project state for contributors. Machine-specific handoff notes are intentionally kept outside version control.

## Current verified workflow

AxiomRE currently supports one deliberately narrow native-analysis path:

1. open a Windows PE32/PE32+ executable or library;
2. inspect bounded PE metadata, sections, named/ordinal imports, named/ordinal-only/forwarded exports, strings and SHA-256 with the owned core parser;
3. start a persistent REA/Ghidra MCP session for deep analysis;
4. enumerate analyzed procedures;
5. inspect a provider-neutral function dossier with pseudocode, assembly, callers/callees and typed references;
6. navigate by canonical address, function name, imported API/DLL or foundation string;
7. inspect the exact address as decoded instruction, data, non-boundary, undecodable or outside-memory evidence;
8. compare bounded original file bytes with provider-loaded memory bytes;
9. attach analyst-owned aliases/comments;
10. save and reopen `.axiomre` project state after verifying the target SHA-256.

The renderer does not consume raw REA/Ghidra JSON and has no direct Node.js or filesystem access. The desktop denies renderer-driven top-level navigation, child windows and webview attachment; IPC strings/byte-window lengths are validated at the main-process boundary. Explicit binary/project opens refresh the provider session transactionally so an invalid replacement cannot leave path/report state split or reuse stale Ghidra analysis.

The sandboxed preload is deliberately built as CommonJS (`index.cjs`) while the Electron main process remains ESM. This avoids relying on preload ESM behavior that is incompatible with the current sandboxed bridge configuration. REA child scripts launched from Electron explicitly set `ELECTRON_RUN_AS_NODE=1`, so the same provider code behaves consistently under both Node-based smokes and the Electron main process. The potentially expensive first `list_procedures` request has an explicit five-minute MCP timeout and remains cancelable; interactive provider operations retain a one-minute bound.

Foundation PE reads are capped at 512 MiB before allocation, and selected `.axiomre` project files are capped at 4 MiB before JSON parsing. Project creation and parsing share annotation/navigation validation so AxiomRE does not write project files it would later reject.

## Regression baseline

`npm run check` regenerates the project-owned deterministic PE fixture and currently runs 34 tests:

- 18 core tests;
- 16 provider-adapter tests.

The deterministic fixture is `fixtures/pe/minimal-x64.exe`. It is produced entirely by `scripts/generate-fixtures.mjs` and contains one minimal x64 entry function.

A real Ghidra/REA smoke against that fixture has verified:

- one recovered local `entry` procedure;
- persistent-session inventory reuse;
- function decompilation and assembly;
- exact instruction decoding at the entry point and `not-instruction-boundary` evidence for an interior byte;
- interior-address-to-procedure resolution;
- bounded provider byte reads.

The owned PE import parser has also been exercised against `choice.exe`, recovering 86 imports across seven DLLs without import-table limitations. The export parser has been exercised against `kernel32.dll`, recovering 1,671 exports including 206 forwarders without export-table limitations.

Deep smoke testing is optional because it requires a compatible JDK and Ghidra installation. Core CI does not silently install those external tools.

A separate local clone has been validated from scratch with `npm ci` followed by `npm run check`: dependency installation completed with zero reported vulnerabilities, the optional Frida install script remained unapproved, all 34 tests passed, and the full desktop build completed. The ignored machine-specific `WORK_HANDOFF.md` was absent from that clone as intended.

The reproducible desktop demo uses the same deterministic fixture and real provider path. `npm run demo:capture` waits until deep analysis has completed and the recovered `entry` procedure is rendered, captures the renderer through Electron's own `capturePage()` API, writes `docs/assets/axiomre-v0.1-demo.png`, and exits. This has been verified end to end on the development host.

## Performance observations

The first Ghidra analysis is intentionally expensive compared with later navigation. On recent development runs, the project fixture took roughly 15–18 seconds for the first inventory; repeated inventory was ~4 ms, exact instruction inspection ~5–13 ms, address resolution/byte reads ~7–10 ms, and function analysis stayed below a tenth of a second on the same fixture.

This is why interactive analysis retains one provider session per target rather than spawning one-shot REA CLI commands for every user action.

Performance numbers are observations, not contractual benchmarks; they vary by hardware and provider version.

## Current launch blockers

Before a public v0.1 community launch, the project still needs:

- a hosted CI run on supported platforms once a remote is available;
- a final packaging/redistribution license review immediately before release (the current dependency policy/check passes);
- a final public name/trademark decision; `AxiomRE` remains a provisional codename;
- one clean external-contributor onboarding validation once the repository can be shared privately or publicly.

Do not broaden into a debugger, plugin marketplace or additional binary formats before the PE workflow is reliable and the launch gate in `docs/ROADMAP.md` is satisfied.
