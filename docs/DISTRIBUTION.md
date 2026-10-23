# Distribution policy

HexScry v0.1 is distributed as an MPL-2.0 desktop application with a deliberately narrow native-analysis stack.

## Bundled runtime

The packaged application includes HexScry's own compiled code and the production JavaScript dependencies required by the desktop/provider path.

`rea-agents` is an embedded runtime dependency. Its MIT license, third-party notices, runtime license inventory and retained upstream license records must remain available with every binary distribution.

`openpgp` is a transitive REA runtime dependency under LGPL-3.0+. Its license text must be shipped with the application. Release packaging must preserve the rights and notices required by the upstream license; the release audit intentionally fails if the expected license/version metadata changes without review.

## Explicitly not bundled

Ghidra and JADX are external engines supplied separately by the user. HexScry detects/configures them but does not redistribute their executables or claim rights to them.

Frida is an optional REA dependency and is not required by the v0.1 PE/Ghidra workflow. It is explicitly excluded from HexScry packaging. A real Ghidra/REA smoke has been verified with the Frida package physically absent from `node_modules`.

Do not replace this exclusion with `npm prune --omit=optional`: TypeScript 7 uses optional platform packages during development/build, and a broad prune was observed to produce an unsuitable runtime tree. Packaging must filter Frida specifically.

A clean `npm ci` may also warn that the dev-only `electron-winstaller` install script is not approved. Do not blanket-approve it merely to silence npm: HexScry's verified portable/NSIS path passes `release:verify` with that script blocked. Revisit approval only if a future release target demonstrably requires it.

## Packaging layout

HexScry v0.1 deliberately keeps Electron ASAR disabled. REA is invoked as a child-process/runtime with filesystem-backed scripts and bridge assets, so forcing it into ASAR now would require a brittle unpack policy for little user-visible benefit. The release audit treats this as an explicit v0.1 decision: changing ASAR policy requires a fresh packaged-runtime verification.

This is not a permanent architectural requirement. Revisit ASAR only when a concrete packaging, startup or integrity benefit justifies the added path/unpack complexity.

## Release checks

Before producing a public binary:

1. run `npm ci`;
2. run `npm run release:verify` — this performs the full project check, license audit, unpacked Windows build and a packaged deep-analysis smoke against the deterministic PE fixture;
3. inspect the unpacked application contents and retained license resources;
4. only then run `npm run package:win` to create the portable artifact.

`npm run package:smoke` launches the actual `artifacts/win-unpacked/HexScry.exe` through a uniquely named smoke copy with an isolated Chromium profile, opens the project-owned fixture, performs live REA/Ghidra analysis, requires a final-state renderer capture and exits non-zero on failure. Any lingering Chromium utility/GPU children are cleaned up by that unique smoke name so they cannot lock the canonical packaged executable or affect a normal HexScry instance.

`electron-builder.json` is the authoritative package-content policy. Release resources expose HexScry's MPL license, REA's MIT license and third-party notices, REA's retained license inventory, and OpenPGP's LGPL text alongside the application runtime.

Current v0.1 verification targets **functional reproducibility**, not byte-for-byte reproducible NSIS output. Two clean builds from the same source have differed by four bytes while both passed the same packaged deep-analysis smoke. Do not add deterministic-packaging machinery unless release signing, supply-chain verification or another concrete requirement makes the benefit worth the complexity.

Electron/Chromium retain their own upstream notices in the Electron distribution. Re-check actual packaged contents and licenses whenever Electron, REA, OpenPGP, the package manager lockfile or the builder configuration changes.

This document records project release policy; it is not a substitute for legal advice.
