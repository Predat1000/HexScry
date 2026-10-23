# Security policy

HexScry processes executable files and other artifacts that may be malformed or hostile. The project therefore treats analyzed input as untrusted data.

## Design rules

- HexScry must not execute a target binary merely to analyze it.
- Renderer code has no direct Node.js or filesystem access.
- Provider-specific work runs outside the renderer and crosses typed IPC boundaries.
- Reads are bounded where practical; provider output is validated before entering the UI model.
- The current Ghidra workflow uses ephemeral analysis state and does not write changes back to the original executable.
- Project annotations are stored in `.hexscry` files rather than modifying the target.

A feature that weakens one of these boundaries requires explicit security review and a documented reason.

## Reporting a vulnerability

Do not publish exploit details, credentials, private samples, or sensitive crash artifacts in a public issue.

When the repository is publicly hosted on GitHub, use its private security-reporting / Security Advisory channel for vulnerability reports. Until that channel exists, keep sensitive vulnerability details private rather than opening a public issue.

For ordinary non-sensitive defects, use the bug-report template.

## Scope

Security reports are especially useful for:

- unintended execution of analyzed targets;
- path or filesystem escapes;
- renderer sandbox or IPC boundary bypasses;
- command injection through target-controlled data;
- unsafe provider subprocess handling;
- parser resource-exhaustion or unbounded-read issues;
- project-file parsing that can escape intended limits or mutate unrelated files.
