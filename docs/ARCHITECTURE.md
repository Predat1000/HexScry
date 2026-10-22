# Architecture

## Direction

AxiomRE is a workbench, not a single monolithic disassembler. The application owns the user experience, project model, evidence model, plugin contracts, orchestration, caching and comparison workflows. Specialized engines remain isolated behind adapters.

```text
Desktop UI
   |
Preload / typed IPC
   |
Application services
   +-- AxiomRE Core (owned parsers + model)
   +-- Provider adapters
   |     +-- REA
   |     +-- Ghidra
   |     +-- JADX
   |     +-- future debugger backends
   +-- Plugin host (future)
   |
Project database / evidence store (future)
```

## Boundaries

### Renderer
Untrusted UI surface. No direct filesystem access and no Node integration.

### Main process
Owns file dialogs, filesystem access, process spawning, provider adapters and application services.

### Core
Owns stable domain types and parsers that are genuinely useful for us to implement. The core must not depend on React/Electron.

### Providers
Provider output is normalized into AxiomRE models. UI code must not learn Ghidra/REA-specific response structures.

Interactive REA/Ghidra access uses one persistent MCP subprocess/session. `open_binary` selects the target, and the first deep inventory request may trigger Ghidra auto-analysis; later navigation reuses that analyzed session. One-shot REA CLI commands remain useful for diagnostics and automation but are deliberately excluded from the interactive hot path because each CLI invocation owns an isolated provider session.

### Plugin SDK
Small, versioned contracts. We will not implement a large plugin runtime before a second real plugin/analyzer proves the abstraction.

## Evidence model

Every future finding should be able to carry:

- source/provider;
- address or file range when applicable;
- confidence;
- supporting evidence references;
- limitations/unknowns.

## Performance rule

Do not prematurely optimize the shell. Profiling decides. CPU-heavy work must run outside the renderer and may later move to Rust/native workers only when benchmarks justify it.
