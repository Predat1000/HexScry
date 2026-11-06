# HexScry

> **Pre-alpha / local development.** The project is not ready for public promotion yet.

HexScry is a desktop workbench for inspecting Windows executables. Use it to check what a file contains, compare its bytes with Ghidra’s loaded memory and keep notes on the functions you investigate. The project has three engineering principles:

1. **Evidence first.** Conclusions should link back to bytes, instructions, references, symbols, strings, control flow, or provider evidence.
2. **Modular engines.** Do not rebuild mature decompilers for vanity. Integrate strong open tooling where that is the reasonable engineering choice, while keeping our own data model and workflows vendor-independent.
3. **Human + automation.** Automation and AI should accelerate investigation, not hide uncertainty.

![HexScry v0.1 pre-alpha demo](docs/assets/hexscry-v0.1-demo.png)

The screenshot above is generated from the project-owned deterministic PE fixture through the real desktop shell and live REA/Ghidra path; it is not a mockup.

## Current vertical slice

The current vertical slice is intentionally narrow but real:

- open a Windows PE file (`.exe` / `.dll`);
- parse core PE metadata ourselves, with bounded reads;
- list sections, parse named/ordinal imports with IAT RVAs, parse named/ordinal-only/forwarded exports, parse bounded PE base relocations, inspect Debug Directory / CodeView PDB identity, parse TLS Directory and callback addresses, extract bounded printable strings and calculate SHA-256;
- start one persistent REA/Ghidra MCP session per target;
- inventory local/external procedures after Ghidra analysis;
- select a local procedure and inspect normalized pseudocode + assembly;
- navigate resolved callers/callees and typed incoming/outgoing xrefs without exposing provider-specific JSON to the UI;
- inspect an exact address as decoded instruction, data, non-boundary, undecodable or outside-memory evidence;
- compare original file bytes with Ghidra's loaded-memory bytes in a bounded hex evidence view, marking bytes covered by known PE base relocations so loader fixups are not mistaken for unexplained mutation;
- jump by canonical address, function name, imported API/DLL or foundation string using the already-open analysis session, and navigate directly from PE entry-point/TLS-callback evidence after deep analysis;
- save/open a minimal `.hexscry` project that verifies the target SHA-256 before reuse;
- persist analyst-owned aliases/comments per function without modifying Ghidra or the executable;
- regenerate and test a project-owned deterministic PE32+ x64 fixture for legal regression coverage;
- detect local REA / Ghidra / JADX availability in the desktop workbench.

This proves the primary native-analysis path before we broaden into graphs, plugins, debugging or additional binary formats.

## Technology

- Electron + React + TypeScript for the desktop shell;
- `@hexscry/core` for analysis-domain code that we own;
- Ghidra as an optional deep native-analysis provider;
- REA 6.7.0 pinned as an application dependency and wrapped behind `@hexscry/provider-rea`;
- JADX for Android analysis;
- a small plugin SDK whose contracts are versioned separately from the UI.

Heavy analysis belongs out of the renderer process.

## Development

```text
npm ci
npm run doctor
npm run check
npm run dev
```

Node.js 24 is the supported development line (`.nvmrc` / `.node-version`). `npm run doctor` checks the required workspace/tooling state and reports optional deep-analysis dependencies separately, so a missing Ghidra/JDK setup is not confused with a broken core checkout.

### Running the desktop on Ubuntu 24.04

`npm run check` works headlessly. The desktop needs a display and the native Electron libraries. If Electron aborts before the window opens with “The SUID sandbox helper binary was found, but is not configured correctly”, check the kernel journal for an AppArmor denial involving `unprivileged_userns`. On our Ubuntu 24.04 test VM, a path-specific AppArmor profile granting `userns` to an administrator-owned Electron executable allowed the workbench to run with Chromium sandboxing enabled. An administrator can follow the Ubuntu guidance for that specific runtime and set `ELECTRON_OVERRIDE_DIST_PATH` to its distribution directory; use the Electron version from the lockfile. [Ubuntu 24.04 release notes](https://documentation.ubuntu.com/release-notes/24.04/)

### Reproducible demo

```text
npm run demo          # open the project-owned PE fixture with the owned parser
npm run demo:deep     # fixture + live persistent REA/Ghidra analysis
npm run demo:capture  # deep demo, capture the stable renderer, then exit
```

`demo:capture` writes `docs/assets/hexscry-v0.1-demo.png` only after deep analysis has completed and the recovered `entry` procedure is visible. The fixture is generated entirely from project-owned code. Deep demo/capture requires a compatible JDK and Ghidra; these tools are detected rather than silently downloaded.

For a dependency-clean verification equivalent to the CI entry path, run `npm run verify:checkout`. `npm install`/`npm ci` bring the supported REA version. Native Ghidra analysis additionally requires a compatible JDK and `GHIDRA_INSTALL_DIR`; the desktop reports whether those external tools are available instead of silently downloading them.

### Try one investigation

After the development checks above, run `npm run demo`. The sample is a small executable generated from source in this repository.

1. In **Sections**, find `.text` at RVA `0x1000`. Search the strings for `deterministic` to find the embedded fixture marker. Both steps work with the built-in parser.
2. If Ghidra and a compatible JDK are installed, click **Analyze with Ghidra**, then click the **Entry RVA** in the sidebar. **Instruction** shows the decoded instruction. In **Hex**, the first three file bytes are `31 C0 C3`. In **Assembly**, those bytes correspond to XOR EAX,EAX followed by RET.
3. Enter `0x140001001` in the navigation box. It points at the second byte of XOR. Compare the instruction status with the status at `0x140001000` to see how HexScry distinguishes a byte address from an instruction boundary.
4. Select `entry`, give it an alias, add a comment and save the project. Reopen it, select the original binary if prompted (its SHA-256 must match), and run deep analysis again to recover your annotated function.

### Release verification (Windows)

```powershell
npm run release:verify  # check + license audit + unpacked package + packaged deep smoke
npm run package:win     # create the portable Windows artifact after verification
```

The packaged smoke launches the actual built `HexScry.exe`, opens the deterministic fixture, completes live REA/Ghidra analysis and requires a final renderer capture before passing. Ghidra/JADX remain external tools and are not redistributed. See `docs/DISTRIBUTION.md` for the package/license policy.

See `CONTRIBUTING.md` before contributing and `SECURITY.md` for the untrusted-input model and vulnerability-reporting rules.

## Project principles

- Prefer a clear 90–95% solution over a fragile 100% solution.
- Do not add complexity for marginal benchmark wins.
- Keep provider-specific details behind adapters.
- Every meaningful analysis claim should be representable with evidence and confidence.
- Keep the application useful without cloud AI.
- Do not copy proprietary implementation code. Proprietary tools may be studied behaviorally/clean-room where lawful; open-source tools are studied under their licenses.

See `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT_STATE.md`, `docs/ROADMAP.md`, `docs/DECISIONS.md`, `docs/DEPENDENCY_LICENSES.md`, `docs/BRANDING_REVIEW.md`, `docs/RELEASE_CHECKLIST.md`, `docs/RELEASE_PROCESS.md`, and `docs/CONTRIBUTOR_BACKLOG.md`.
