# External contributor onboarding validation

Use this once the repository can be shared. The goal is to test the public project experience, not the contributor's reverse-engineering knowledge.

## Rules for the validation

Give the participant the repository URL (or the private Git bundle) and this file. A bundle can be cloned with `git clone HexScry.bundle HexScry`. Do not give them `WORK_HANDOFF.md`, NUC paths, private chat history or step-by-step coaching unless they are blocked and the block itself is recorded as an onboarding defect.

## Baseline path

1. Clone the repository into a new directory.
2. Read `README.md` and `CONTRIBUTING.md`.
3. Use Node.js 24.
4. Run:

```text
npm ci
npm run doctor
npm run check
```

5. Start the desktop app with `npm run dev`.
6. Open the project-owned fixture through `npm run demo` or the file picker.
7. If they already have a compatible JDK + Ghidra, optionally run `npm run smoke:rea` or `npm run demo:deep`. Deep analysis is not required to validate core onboarding.
8. Pick a current `good first issue`, or use `docs/CONTRIBUTOR_BACKLOG.md` for an offline pilot. Make a focused change or review one proposed change with concrete findings.
9. For a hosted change, prepare a pull request using the repository template. For an offline pilot, retain the local commit or review notes for the maintainer.

## What to record

Record only actionable friction:

- any instruction that was ambiguous or wrong;
- a command that failed on an otherwise supported setup;
- a dependency/version the docs failed to mention;
- a security warning that looked like it required unsafe approval;
- an architecture boundary that was not understandable from public docs;
- a first issue that turned out to require hidden project knowledge;
- approximate time from clone to a passing `npm run check`.

Do not "fix" onboarding by adding broad tooling or hidden automation unless the observed problem justifies it. Prefer correcting the smallest misleading instruction, script or contract.

## Passing result

The launch gate is satisfied when one external participant can, without private guidance:

- obtain a clean checkout;
- get the required doctor checks green;
- run `npm run check` successfully;
- understand which deep-analysis dependencies are optional;
- make or meaningfully review one small contribution while respecting the core/provider/renderer boundaries.

Any failure is useful evidence. Fix the repository, reset the test environment, and repeat the affected path before marking this gate complete.
