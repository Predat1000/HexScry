# Contributing to HexScry

HexScry is pre-alpha. Contributions are welcome once the repository is opened publicly, but the current architecture is intentionally narrow while the PE workflow stabilizes.

## Development setup

Requirements:

- Node.js 24.x;
- npm;
- Git.

From a clean checkout:

```powershell
npm ci
npm run check
npm run dev
```

`npm run check` regenerates the project-owned PE fixture, runs strict typechecking and tests, then builds every workspace.

REA currently declares Frida as an optional dependency. npm may report its native install script as unapproved; the static Ghidra workflow does not require it, and contributors should not approve optional native install scripts unless a feature explicitly needs them and the security implications have been reviewed.

## Optional deep-analysis setup

Core parser tests do not require Ghidra. To exercise the real native-analysis smoke test, install a compatible JDK and Ghidra, set `JAVA_HOME` and `GHIDRA_INSTALL_DIR`, then run:

```powershell
npm run smoke:rea
```

The smoke uses `fixtures/pe/minimal-x64.exe`, which is generated entirely from project-owned code.

## Architecture boundaries

- `packages/core` owns provider-neutral analysis models, parsers and project state.
- `packages/provider-rea` owns all REA/Ghidra transport and response normalization.
- `apps/desktop` owns Electron IPC and the React workbench.
- React must not consume raw REA/Ghidra response structures.
- The renderer must not receive direct Node.js or filesystem access.
- Heavy analysis must stay outside the renderer process.

Add an abstraction only when at least one real workflow needs it. Prefer a small explicit contract over a speculative framework.

## Evidence and verification

A successful command response is not automatically proof of the intended effect. Verify observable state after writes, mutations and provider operations. Keep limitations explicit rather than turning unknowns into guesses.

When changing parsing or provider behavior, add a regression test. Extend the self-built fixture corpus only when a new property is genuinely required.

## Legal and clean-room rules

Do not contribute proprietary source code, decompiler code, leaked symbols, copyrighted binary fixtures, credentials, private data or assets without redistribution rights.

Proprietary tools may inform behavior-level compatibility work where lawful, but implementations must be original. Open-source integrations must respect their licenses and attribution requirements.

## Pull requests

Keep changes focused. A useful PR should explain:

- the user-visible or engineering problem;
- the chosen approach and important tradeoffs;
- how it was verified;
- known limitations or follow-up work.

Before requesting review, run `npm run check`. If your change touches the REA/Ghidra adapter and you have the external toolchain installed, also run `npm run smoke:rea`.

Do not bundle unrelated refactors with feature or bug-fix work unless the refactor is necessary for the change.
