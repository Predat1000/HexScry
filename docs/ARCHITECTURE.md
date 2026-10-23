# Architecture

## Direction

HexScry is a workbench, not a single monolithic disassembler. The application owns the user experience, project model, evidence model, plugin contracts, orchestration, caching and comparison workflows. Specialized engines remain isolated behind adapters.

```text
Desktop UI
   |
Preload / typed IPC
   |
Application services
   +-- HexScry Core (owned parsers + model)
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

### Preload bridge
Small typed IPC surface exposed through `contextBridge`. The preload is deliberately emitted as CommonJS (`index.cjs`) while remaining sandboxed with context isolation enabled; this is a compatibility boundary, not permission to move application logic into preload.

### Main process
Owns file dialogs, filesystem access, process spawning, provider adapters and application services.

### Core
Owns stable domain types and parsers that are genuinely useful for us to implement. The core must not depend on React/Electron. PE base relocations are core evidence: loader-fixup coverage is derived from the file itself and can annotate file-vs-memory differences independently of whichever deep-analysis provider is active. Debug Directory / CodeView identity is also core evidence: PDB path, RSDS/NB10 identity, GUID/age and other debug-directory entry types come directly from bounded PE bytes rather than from Ghidra-specific output. TLS Directory metadata and callback VAs are likewise core evidence because callbacks can execute before the ordinary PE entry point; the parser records them independently and deep providers may later corroborate whether each callback resolves to executable code.

### Providers
Provider output is normalized into HexScry models. UI code must not learn Ghidra/REA-specific response structures.

Interactive REA/Ghidra access uses one persistent MCP subprocess/session. `open_binary` selects the target, and the first deep inventory request may trigger Ghidra auto-analysis; later navigation reuses that analyzed session. When spawned by Electron, REA runs through Electron's Node runtime mode (`ELECTRON_RUN_AS_NODE=1`) so provider behavior matches Node-based smoke tests. The deep inventory request has a bounded five-minute timeout and remains cancelable; interactive requests retain shorter bounds. One-shot REA CLI commands remain useful for diagnostics and automation but are deliberately excluded from the interactive hot path because each CLI invocation owns an isolated provider session.

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
