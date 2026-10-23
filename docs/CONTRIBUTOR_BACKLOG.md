# Initial contributor backlog

These are candidate GitHub issues for the first community launch. They are deliberately small, testable and useful. Do not publish all of them blindly; convert the best current items into issues after hosted CI is live.

## Good first issue — decode PE section characteristics

**Goal:** show human-readable PE section flags alongside the raw characteristics value.

Scope:
- decode common flags such as `CODE`, `INITIALIZED_DATA`, `UNINITIALIZED_DATA`, `EXECUTE`, `READ` and `WRITE` in `@hexscry/core`;
- preserve the raw numeric value;
- render decoded flags in the existing section evidence UI;
- add synthetic regression tests.

Acceptance:
- no new dependency;
- malformed/unknown bits remain representable rather than discarded;
- `npm run check` passes.

Suggested labels: `good first issue`, `core`, `PE`, `UI`.

## Good first issue — client-side filter for PE evidence tables

**Goal:** make Imports, Exports and Strings easier to inspect without triggering provider calls.

Scope:
- one small filter input reused by the active evidence tab;
- case-insensitive substring matching;
- filtering stays entirely in the renderer over already-loaded bounded data;
- show visible/total counts.

Acceptance:
- no REA/Ghidra calls are added;
- empty filter restores the full bounded list;
- keyboard interaction remains usable.

Suggested labels: `good first issue`, `UI`, `UX`.

## Good first issue — copy evidence values

**Goal:** allow analysts to copy addresses, hashes and symbol names without selecting text manually.

Scope:
- add a small reusable copy action for canonical addresses and SHA-256 values;
- use browser clipboard APIs from the renderer; do not expose Node or filesystem access;
- provide short visual confirmation without adding a notification framework.

Acceptance:
- respects the current Electron sandbox/context-isolation boundary;
- no new dependency;
- works for at least entry point, function address and SHA-256.

Suggested labels: `good first issue`, `UI`, `security-boundary`.

## Good first issue — add one targeted PE fixture variant

**Goal:** strengthen the legal/self-built regression corpus with one property we currently cover only through synthetic in-memory construction.

Preferred first variant: a deterministic PE32 fixture that exercises a 32-bit TLS callback or ordinal import end-to-end.

Acceptance:
- fixture is generated entirely by project-owned code;
- file is small and deterministic;
- parser test asserts only properties that the generator intentionally controls;
- documentation explains why the new fixture exists.

Suggested labels: `good first issue`, `tests`, `PE`.

## Help wanted — Linux CI compatibility fixes

Create only if hosted Linux CI reveals a concrete failure. Do not invent portability work before evidence exists.

Acceptance should be the smallest change that makes the failing CI job pass without weakening Windows behavior or silently skipping checks.

Suggested labels: `help wanted`, `CI`, `Linux`.

## Not first-contributor work

Do not label debugger backends, a plugin marketplace, new binary formats, AI agents, CFG rendering or decompiler replacement as `good first issue`. Those features cross architecture boundaries and should wait until the contributor has context and the v0.1 launch gate is closed.
