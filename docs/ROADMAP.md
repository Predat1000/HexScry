# Roadmap

Roadmap items are outcomes, not promises of dates.

## v0.0.x — Foundation
- [x] Repository structure and build pipeline
- [x] Core PE metadata parser
- [x] Bounded strings extraction
- [x] SHA-256 identity
- [x] Desktop shell and typed IPC
- [x] Toolchain status surface
- [x] Minimal project persistence with target SHA-256 verification
- [x] Deterministic self-built x64 PE corpus fixture + regression test
- [x] Bounded PE import parsing (named + ordinal) with IAT RVAs
- [x] Bounded PE export parsing (named + ordinal-only + forwarders)
- [x] Bounded PE base-relocation parsing with loader-fixup evidence in Hex view
- [x] Bounded PE Debug Directory + CodeView RSDS/NB10 PDB identity parsing
- [x] Provider diagnostics that preserve REA evidence and add only evidence-backed setup hints
- [x] Transactional target refresh + bounded project/PE input + Electron navigation/IPC hardening

## v0.1 Alpha — Real reversing workflow
- [x] Persistent REA/Ghidra MCP session + normalized function inventory
- [x] Function selection + Ghidra pseudocode/assembly dossier
- [x] Resolved caller/callee navigation inside the live session
- [x] General navigation by address/function/foundation string
- [x] Typed incoming/outgoing cross references from the function dossier
- [x] Arbitrary-address instruction inspection with decoded/non-boundary/data status
- [x] Hex evidence view comparing original file bytes with Ghidra loaded memory and annotating known relocation coverage
- [x] Analyst-owned comments and aliases persisted in `.axiomre` projects
- [x] Basic project save/load
- [x] Reproducible real-analysis demo + first screenshot asset
- [x] Contributor-ready CI, issue/PR templates, security and contribution docs

**Community launch gate:** v0.1 becomes public/promoted only when a clean checkout builds reliably, the demo workflow is real, and documentation is sufficient for an external contributor to fix a small issue without private guidance.

## v0.2
- [ ] CFG and call graph
- [ ] Search
- [ ] Patch workspace + explicit diff
- [ ] REA evidence investigations
- [ ] Plugin runtime based on proven needs

## Later
- debugging backends;
- Android/JADX workspace;
- IL2CPP and game-focused analyzers;
- firmware workflows;
- benchmark corpus and regression scorecards;
- optional local/cloud AI providers.
