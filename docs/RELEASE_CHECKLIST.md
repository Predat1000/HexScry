# v0.1 community launch checklist

This checklist is intentionally conservative. HexScry should be public when the existing PE workflow is trustworthy and easy to verify, not when every future feature exists.

## Source and identity

- [x] Public product/repository name selected: `HexScry`.
- [x] Package/workspace scopes use `@hexscry/*`.
- [x] Project format uses `.hexscry` / `hexscry-project`.
- [x] App identity uses `org.hexscry.workbench`.
- [ ] Repeat GitHub/npm/general-web name checks immediately before the first public tag.
- [ ] Perform the appropriate formal trademark review before presenting HexScry as a stable commercial brand.

## Build and verification

- [x] `npm run check` passes locally.
- [x] `npm run doctor` reports required development checks clearly.
- [x] Clean post-rename checkout passes `npm ci` and `npm run release:verify`.
- [x] Clean post-rename checkout builds and deep-smokes the Windows portable artifact.
- [ ] Hosted Windows CI passes from the public/private GitHub remote.
- [ ] Hosted Linux CI passes from the public/private GitHub remote.
- [ ] One person outside the primary development session follows only README/CONTRIBUTING and completes the validation in `docs/EXTERNAL_ONBOARDING.md`, including one small contribution or meaningful review.

## Release artifact

- [x] Windows unpacked package deep-smokes against the project-owned PE fixture.
- [x] Windows portable self-extracting artifact deep-smokes against the same fixture.
- [x] Release audit confirms bundled/external dependency policy.
- [ ] From the candidate lockfile, run `npm ci` and `npm audit --omit=dev --audit-level=high`. Resolve high/critical runtime findings before distribution. Record outstanding moderate advisories, whether the affected versions are bundled, and how the desktop invokes them. Verify dependency fixes with the packaged deep smoke.
- [ ] Bump all npm workspaces to `0.1.0-alpha.1` only after the launch gate is green.
- [ ] Build `HexScry 0.1.0-alpha.1.exe` from the final tagged source following `docs/RELEASE_PROCESS.md`.
- [ ] Record final artifact size and SHA-256 in release notes.
- [ ] Inspect packaged license resources and confirm optional Frida is absent.
- [ ] Inspect the final screenshot/demo generated from the tagged source.

## Repository hygiene

- [x] `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, roadmap, architecture and decision docs exist.
- [x] Issue and pull-request templates exist.
- [x] Machine-specific `WORK_HANDOFF.md`, evidence and release artifacts are ignored.
- [x] `npm run source:audit` scans tracked/reachable Git history for forbidden local artifacts, absolute user-home paths and high-signal credential patterns; CI and release verification run it with full history.
- [ ] GitHub remote configured following `docs/GITHUB_BOOTSTRAP.md`.
- [ ] Branch protection / required CI checks configured where available.
- [ ] GitHub private vulnerability reporting / Security Advisories enabled so `SECURITY.md` has a real private channel.
- [ ] Initial community issues created from `docs/CONTRIBUTOR_BACKLOG.md`.
- [ ] GitHub Discussions enabled if useful after the first contributor arrives; do not enable empty community surfaces just for appearance.

## Launch message

The first announcement must describe what works today, not promise IDA parity. Use `docs/COMMUNITY_LAUNCH_DRAFT.md` as the starting copy, then refresh concrete revision/count/hash details from the final tag. It should show the real demo, name current limits (PE/x86-64-focused vertical slice, Ghidra/JDK needed for deep analysis), link contribution docs, and point newcomers to small well-scoped issues.
