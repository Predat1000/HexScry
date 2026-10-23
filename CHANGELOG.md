# Changelog

All notable public changes to HexScry will be documented here. The project follows Semantic Versioning once public prereleases begin.

## Unreleased

### Added
- evidence-first Windows PE workbench with bounded project-owned parsing;
- PE sections, imports, exports, strings, base relocations, Debug Directory / CodeView identity and TLS callbacks;
- persistent REA/Ghidra analysis sessions with normalized procedure inventory;
- function pseudocode, assembly, callers/callees and typed xrefs;
- exact-address instruction evidence and containing-procedure resolution;
- original-file vs loaded-memory byte comparison with relocation coverage;
- `.hexscry` project persistence with SHA-256 target verification, aliases and comments;
- deterministic project-owned PE fixture and 42-test baseline;
- dependency/license audit, environment doctor, Windows packaging/deep-smoke pipeline and contributor launch documentation.

### Known limitations
- current public-alpha target is a PE-focused native-analysis vertical slice rather than broad format/architecture parity;
- Ghidra/JDK are separately installed requirements for deep native analysis;
- no debugger, CFG/call-graph UI, Android workspace or plugin runtime in the first alpha;
- Windows portable packaging is functionally reproducible but not byte-for-byte reproducible.

## Planned — 0.1.0-alpha.1

The first public tag will be created only after hosted Windows/Linux CI and the external onboarding gate pass. At release time, move the relevant `Unreleased` content here, add the release date, final artifact hash and any last-minute limitations discovered by the tagged-source verification.
