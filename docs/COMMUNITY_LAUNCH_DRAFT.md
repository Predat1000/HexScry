# Community launch draft

This is the launch copy for the first public HexScry alpha. Update concrete revision/hash details immediately before publishing.

## GitHub repository description

Open-source reverse-engineering workbench for evidence-first PE analysis, persistent Ghidra/REA workflows, pseudocode, assembly, xrefs, exact instruction evidence, hex comparison and reproducible analyst projects.

## Short announcement

**HexScry v0.1 alpha is open for contributors.**

HexScry is an open-source reverse-engineering workbench built around a simple rule: analysis claims should stay connected to evidence.

The first alpha deliberately focuses on a real Windows PE workflow rather than promising every format and architecture at once. Today HexScry can parse PE evidence itself, keep a persistent REA/Ghidra analysis session, navigate procedures/xrefs, inspect exact instructions, compare original bytes with loaded-memory bytes, persist analyst annotations, and reproduce the workflow against a project-owned test binary.

The project is designed to remain useful without cloud AI and to integrate mature open tooling rather than reimplementing it for vanity. Provider-specific data stays behind adapters so the HexScry model and UI are not synonymous with Ghidra.

This is an alpha, not an IDA replacement claim. The current vertical slice is strongest on Windows PE/x86-64 analysis, deep analysis requires a compatible JDK + Ghidra, and graphs/debugging/additional formats are intentionally later work.

If you want to contribute, start with the README and CONTRIBUTING guide. The initial issues are intentionally small and testable so a first contribution does not require understanding the whole architecture.

## Release highlights

- bounded, project-owned PE parser for metadata, sections, imports, exports, relocations, CodeView/PDB identity and TLS callbacks;
- persistent REA/Ghidra MCP session so the expensive first analysis is reused for interactive navigation;
- normalized pseudocode + assembly function dossiers;
- callers/callees and typed xrefs;
- exact-address instruction status instead of forcing every address into a function abstraction;
- original-file vs loaded-memory byte evidence with relocation coverage;
- navigation by address, procedure, imported symbol/DLL and bounded string evidence;
- `.hexscry` projects with SHA-256 target verification, aliases and comments;
- deterministic project-owned PE fixture, 42-test baseline, license audit and Windows packaged/portable deep smokes;
- Windows + Linux hosted CI configuration ready for the public repository.

## Current limitations

- v0.1 is a PE-focused vertical slice, not broad format parity;
- native deep analysis currently relies on separately installed Ghidra/JDK;
- JADX is detected but the Android workspace is not a v0.1 workflow yet;
- no debugger backend yet;
- no CFG/call-graph UI yet;
- no plugin marketplace/runtime yet;
- Windows portable artifacts are functionally reproducible, not byte-for-byte reproducible;
- the project is pre-stable and schemas/APIs may evolve before 1.0.

## Contributor call

Good first contributions should improve an existing workflow without widening architecture unnecessarily. Early examples include readable PE section flags, lightweight evidence-table filtering, safe copy actions for evidence values and targeted self-built fixture variants.

Larger areas such as debugger backends, new binary formats, CFG rendering and plugin runtime are intentionally not first-contributor tasks until the v0.1 workflow and community process have settled.

## Launch rule

Do not publish this text until hosted CI has passed and the final release checklist is complete. Replace any stale counts, hashes or limitations with the tagged-source state immediately before publication.
