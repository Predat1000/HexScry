# Release process

HexScry uses a deliberately small release process. The goal is a verifiable artifact, not release automation for its own sake.

## Planned first public release

- Version: `0.1.0-alpha.1`
- Tag: `v0.1.0-alpha.1`
- Windows portable artifact: `HexScry 0.1.0-alpha.1.exe`
- License: MPL-2.0 for HexScry source; bundled/external dependencies retain their own licenses.

The current `0.0.1` artifacts are local pre-alpha verification builds and must not be uploaded as the first community release.

## Preflight

1. Hosted Windows and Linux CI must be green on the intended release commit.
2. Complete `docs/RELEASE_CHECKLIST.md` through the final-artifact items.
3. Repeat name/package checks and review dependency/license output.
4. Confirm `git status` is clean and the intended commit is on `main`.
5. Run `npm run doctor` and `npm run check` locally.
6. On the Windows release host with JDK + Ghidra configured, run `npm run release:verify`.

## Version bump

Only after the gate is green, update the root and all npm workspaces together without creating a tag yet:

```text
npm version 0.1.0-alpha.1 --workspaces --include-workspace-root --no-git-tag-version
npm run check
```

Review `package.json`, workspace package files and `package-lock.json`. The version-change commit should contain no unrelated code changes. This exact command was verified in a disposable clone on 2026-10-23: it changed only the root package, the four workspace package versions and the lockfile version metadata.

## Final artifact

On Windows:

```text
npm run release:verify
npm run package:win
```

Then:

- deep-smoke the final portable through `scripts/smoke-packaged.mjs`;
- inspect packaged license resources;
- confirm optional Frida is absent;
- regenerate/inspect the demo capture from the same release source;
- record file size and SHA-256.

Do not promise byte-for-byte reproducible NSIS output for v0.1; functional clean-build reproducibility is the current requirement.

## Tag and publish

1. Commit the version bump and final release-note changes.
2. Ensure hosted CI passes on that exact commit.
3. Create annotated tag `v0.1.0-alpha.1` on that commit.
4. Build/reverify the Windows portable from the tagged source if the final CI/tag operation changed anything material.
5. Create the GitHub prerelease, attach the verified portable and publish SHA-256 in the notes.
6. Use `docs/COMMUNITY_LAUNCH_DRAFT.md` as the launch copy, refreshing counts/limits from the tag.
7. Create the selected starter issues from `docs/CONTRIBUTOR_BACKLOG.md` and point newcomers to them.

## After publication

Treat alpha feedback as evidence. Fix real onboarding, correctness and workflow problems before broadening scope. Do not rush `alpha.2` for cosmetic churn; release another alpha when users need a coherent set of fixes or a meaningful workflow improvement.
