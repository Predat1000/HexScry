# Engineering decisions

## D001 — Public name: HexScry
**Status:** accepted for launch; re-check before the first public tag.

Reason: the original working name `AxiomRE` acquired a known collision risk with an existing AxiomRe business identity. `HexScry` had no exact GitHub or npm software collision in the 2026-10-23 review, no obvious public reverse-engineering/security product collision, and fits the evidence-first binary-analysis identity. The rename was deliberately completed before any public repository or project-format compatibility promise existed. See `docs/BRANDING_REVIEW.md`.

## D002 — Desktop shell: Electron + React + TypeScript
**Status:** accepted for the first product stages.

Reason: fastest path to a polished cross-platform workbench with a large contributor pool. Heavy binary analysis is isolated from the renderer. We will not rewrite the application in Rust merely for lower idle RAM; a native migration requires profiling evidence and a clear user benefit.

## D003 — Core/providers separation
**Status:** accepted.

Reason: HexScry must not become a skin whose internal model is synonymous with Ghidra. Provider adapters normalize external results.

## D004 — License: MPL-2.0
**Status:** accepted, to be revalidated before public launch.

Reason: file-level copyleft keeps modifications to project files open while remaining friendly to a broad plugin/integration ecosystem. Dependencies keep their own licenses.

## D005 — No marginal-complexity improvements
**Status:** permanent project rule.

A change that creates substantial architecture/maintenance cost for a tiny practical gain is rejected unless profiling or a concrete use case demonstrates otherwise.

## D006 — Clean-room boundary for proprietary tools
**Status:** permanent project rule.

We may compare documented or observable behavior of proprietary tools where lawful. We do not copy proprietary implementation code, bypass licensing/DRM to obtain it, or incorporate protected assets.

## D007 — Sandboxed preload stays CommonJS
**Status:** accepted.

The Electron main process remains ESM, but the sandboxed preload is built explicitly as CommonJS (`index.cjs`). This keeps `contextIsolation` and the sandbox enabled while avoiding preload-module loading ambiguity observed in Electron 45. Do not switch the preload back to ESM unless a supported configuration is proven by a real desktop smoke.

## D008 — REA child processes use Electron's Node mode
**Status:** accepted.

When HexScry launches REA from the Electron main process, `process.execPath` points at `electron.exe`. Provider child processes therefore set `ELECTRON_RUN_AS_NODE=1` so the same `rea.mjs` entrypoint behaves consistently under Electron and ordinary Node. The first procedure inventory may trigger Ghidra auto-analysis and gets a bounded five-minute MCP timeout; later interactive operations remain bounded to one minute and support cancellation.
