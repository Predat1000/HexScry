# Dependency and redistribution review

This is an engineering release checklist, not the final third-party notice file.

## Project license

AxiomRE-owned source files are currently licensed under MPL-2.0. The root package and all internal npm workspaces declare `license: MPL-2.0`.

## Current npm snapshot

The release lockfile is dominated by permissive licenses (MIT, Apache-2.0, ISC, BSD-family, BlueOak) plus MPL-2.0 packages.

Two transitive dependencies of `rea-agents` require explicit packaging attention:

- `openpgp` 6.3.2 — LGPL-3.0+. It is a normal REA dependency.
- `frida` 17.23.2 — LGPL-2.0 with WxWindows exception. REA marks it optional. AxiomRE's current static Ghidra workflow does not require it, and its native install script remains deliberately unapproved.

Relevant direct/runtime packages checked locally:

- `rea-agents` 6.7.0 — MIT.
- Electron 45.0.0 — MIT.
- React 19.3.1 — MIT.
- `@modelcontextprotocol/sdk` 1.32.1 — MIT in the installed package metadata.

## v0.1 packaging policy

1. Do not silently approve or bundle Frida merely because REA offers it. Add it only when a real feature requires it and review security/licensing first.
2. If a desktop package includes REA and `openpgp`, keep the LGPL component separable/replaceable rather than flattening it irreversibly into AxiomRE-owned code. Preserve the applicable license text and satisfy source/replacement requirements for the exact distribution format.
3. Generate third-party notices from the exact release lockfile for every public binary release.
4. Ghidra, the JDK and JADX remain external optional tools for v0.1. Do not bundle them in an AxiomRE installer until redistribution terms and their bundled notices have been reviewed for that concrete package.
5. Third-party packages retain their own licenses. MPL-2.0 applies to AxiomRE-owned files, not to dependencies.

## Current conclusion

No dependency found in this review requires abandoning MPL-2.0 or the current architecture. The main release-engineering constraint is correct LGPL handling for `openpgp` if REA ships inside the desktop distribution, while optional Frida remains excluded unless deliberately enabled.
