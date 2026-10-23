# Development state

This document summarizes the portable project state for contributors. Machine-specific handoff notes are intentionally kept outside version control.

## Current verified workflow

HexScry currently supports one deliberately narrow native-analysis path:

1. open a Windows PE32/PE32+ executable or library;
2. inspect bounded PE metadata, sections, named/ordinal imports, named/ordinal-only/forwarded exports, base relocations, Debug Directory / CodeView PDB identity, TLS Directory/callbacks, strings and SHA-256 with the owned core parser;
3. start a persistent REA/Ghidra MCP session for deep analysis;
4. enumerate analyzed procedures;
5. inspect a provider-neutral function dossier with pseudocode, assembly, callers/callees and typed references;
6. navigate by canonical address, function name, imported API/DLL or foundation string, or jump directly from PE entry-point/TLS-callback evidence once deep analysis is available;
7. inspect the exact address as decoded instruction, data, non-boundary, undecodable or outside-memory evidence;
8. compare bounded original file bytes with provider-loaded memory bytes, marking coverage from known PE base relocations so loader fixups are visible evidence rather than unexplained byte changes;
9. attach analyst-owned aliases/comments;
10. save and reopen `.hexscry` project state after verifying the target SHA-256.

The renderer does not consume raw REA/Ghidra JSON and has no direct Node.js or filesystem access. The desktop denies renderer-driven top-level navigation, child windows and webview attachment; IPC strings/byte-window lengths are validated at the main-process boundary. Explicit binary/project opens refresh the provider session transactionally so an invalid replacement cannot leave path/report state split or reuse stale Ghidra analysis.

The sandboxed preload is deliberately built as CommonJS (`index.cjs`) while the Electron main process remains ESM. This avoids relying on preload ESM behavior that is incompatible with the current sandboxed bridge configuration. REA child scripts launched from Electron explicitly set `ELECTRON_RUN_AS_NODE=1`, so the same provider code behaves consistently under both Node-based smokes and the Electron main process. The potentially expensive first `list_procedures` request has an explicit five-minute MCP timeout and remains cancelable; interactive provider operations retain a one-minute bound.

Foundation PE reads are capped at 512 MiB before allocation, and selected `.hexscry` project files are capped at 4 MiB before JSON parsing. Project creation and parsing share annotation/navigation validation so HexScry does not write project files it would later reject.

## Regression baseline

`npm run check` regenerates the project-owned deterministic PE fixture and currently runs 42 tests:

- 26 core tests;
- 16 provider-adapter tests.

The deterministic fixture is `fixtures/pe/minimal-x64.exe`. It is produced entirely by `scripts/generate-fixtures.mjs` and contains one minimal x64 entry function.

A real Ghidra/REA smoke against that fixture has verified:

- one recovered local `entry` procedure;
- persistent-session inventory reuse;
- function decompilation and assembly;
- exact instruction decoding at the entry point and `not-instruction-boundary` evidence for an interior byte;
- interior-address-to-procedure resolution;
- bounded provider byte reads.

The owned PE import parser has also been exercised against `choice.exe`, recovering 86 imports across seven DLLs without import-table limitations. The export parser has been exercised against `kernel32.dll`, recovering 1,671 exports including 206 forwarders without export-table limitations. The base-relocation parser has been exercised against `notepad.exe` (361 `DIR64` relocations) and `kernel32.dll` (432 `DIR64` relocations) without relocation-table limitations. Debug Directory parsing has been exercised against the same Windows binaries: `notepad.exe` exposes `notepad.pdb` with an RSDS GUID/age plus POGO and REPRO entries; `kernel32.dll` exposes `kernel32.pdb` with RSDS identity plus POGO, REPRO and `EX_DLLCHARACTERISTICS` entries, without debug-directory parsing errors. TLS parsing has been sampled across System32: examples with live callbacks include `ActivationClient.dll` (2), `Chakra.dll` (1), `CloudRestoreLauncher.dll` (2) and `convertvhd.exe` (1), all with valid image-relative callback addresses and no TLS parsing limitations.

Deep smoke testing is optional because it requires a compatible JDK and Ghidra installation. Core CI does not silently install those external tools.

A post-rename `git clone --no-local` of identity commit `cff4475` has now been validated from scratch. After a single clean `npm ci`, the clone installed 572 packages with zero reported vulnerabilities; Frida and the dev-only `electron-winstaller` install scripts remained unapproved. It passed all 42 tests, the full desktop build, release-license audit, unpacked Windows packaging and the actual packaged deep smoke via `npm run release:verify` (77,008-byte final-state capture). It then built `HexScry 0.0.1.exe` at 111,764,507 bytes with SHA-256 `DDC46284343159CB0EE1F224BDFC781BB5775BD73DA3024DEEA5377B180406E9` and passed a second deep smoke through the real self-extracting path (76,649-byte final-state capture). This proves the HexScry release path does not depend on the primary checkout's existing `node_modules`, ignored handoff/evidence files or prior build artifacts.

A second clean clone at onboarding commit `ea38825` validated the contributor entry path specifically: `npm ci` again installed 572 packages with zero reported vulnerabilities, `npm run doctor` reported all six required checks passing, and `npm run check` completed the 42-test baseline, license policy, strict typechecks and full workspace build. This is an internal clean-room onboarding simulation; it does **not** replace the still-required external-person validation in `docs/EXTERNAL_ONBOARDING.md`.

The reproducible desktop demo uses the same deterministic fixture and real provider path. `npm run demo:capture` waits until deep analysis has completed and the recovered `entry` procedure is rendered, captures the renderer through Electron's own `capturePage()` API, writes `docs/assets/hexscry-v0.1-demo.png`, and exits. This has been verified end to end on the development host.

Windows distribution now has a local release gate. `npm run release:verify` passes the full project check, release-license audit, `electron-builder` unpacked build and a deep smoke of the actual packaged `artifacts/win-unpacked/HexScry.exe`. The smoke launches a uniquely named copy so remote-session Chromium children cannot lock the canonical executable; the latest HexScry-branded final-state capture was 77,008 bytes. The package contains HexScry core/provider + REA 6.7.0, excludes optional Frida, exposes required HexScry/REA/OpenPGP license resources, and leaves Ghidra/JADX external. ASAR is deliberately disabled for v0.1 because REA uses filesystem-backed child-process/bridge assets; changing that policy requires a fresh packaged-runtime review.

The current Windows portable target has also been built and exercised through its real self-extracting path under the HexScry identity. `artifacts/HexScry 0.0.1.exe` is 111,764,510 bytes (106.59 MiB), SHA-256 `AAD9F2C6C15EF2EA70CCC734AC1AFC03ED3933C87CF3FA302B903B93270C7D78`. A portable smoke confirmed auto-extraction, packaged Electron startup with app ID `org.hexscry.workbench`, REA/Ghidra/JADX detection, live Ghidra recovery of the fixture `entry` procedure, a 77,008-byte final-state capture, and clean shutdown. The release process targets functional reproducibility rather than byte-for-byte NSIS identity; public release artifacts must be rebuilt and rehashed from the final tagged source.

## Performance observations

The first Ghidra analysis is intentionally expensive compared with later navigation. On recent development runs, the project fixture took roughly 15–18 seconds for the first inventory; repeated inventory was ~4 ms, exact instruction inspection ~5–13 ms, address resolution/byte reads ~7–10 ms, and function analysis stayed below a tenth of a second on the same fixture.

This is why interactive analysis retains one provider session per target rather than spawning one-shot REA CLI commands for every user action.

Performance numbers are observations, not contractual benchmarks; they vary by hardware and provider version.

## Current launch blockers

Before the public `v0.1.0-alpha.1` community launch, the project still needs:

- a hosted CI run on supported platforms once a remote is available;
- one external-contributor onboarding validation once the repository can be shared privately or publicly;
- repeat the name/package/trademark checks and the already-passing release/license/package verification immediately before the public tag, then inspect and hash the final portable artifact.

Do not broaden into a debugger, plugin marketplace or additional binary formats before the PE workflow is reliable and the launch gate in `docs/ROADMAP.md` is satisfied.
