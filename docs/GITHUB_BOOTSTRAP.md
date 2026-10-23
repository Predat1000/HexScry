# GitHub bootstrap

HexScry currently has no GitHub remote. The linked GitHub connector can read/write existing repositories but does not expose repository creation, and the NUC intentionally has no borrowed/persisted GitHub token.

## Repository to create

- Owner: connected GitHub account (`Predat1000` at the time of preparation)
- Repository name: `HexScry`
- Initial visibility: **private** while hosted CI and external onboarding are validated
- Do not initialize with README, license, `.gitignore`, or starter files; the local repository already contains the canonical history.
- Default branch after push: `main`

Do not make it public immediately after creation. First use the private remote to prove hosted CI and repository settings.

## First push from the NUC

Once GitHub authentication is available on the NUC, from the existing local repository:

```text
git remote add origin https://github.com/Predat1000/HexScry.git
git remote -v
git push -u origin main
```

Before pushing, confirm the actual repository owner/URL rather than copying this historical value blindly.

## Hosted-CI gate

After the first push:

1. wait for `.github/workflows/ci.yml` on `windows-latest` and `ubuntu-latest`;
2. inspect both jobs, including the `npm run doctor` step;
3. fix real platform failures in the smallest reasonable way;
4. require the CI check on pull requests if repository settings allow it;
5. do not weaken tests or skip Linux just to turn the badge green.

The deep Ghidra smoke is intentionally not part of hosted baseline CI because it requires a separately installed heavy toolchain. Windows release/deep-smoke verification remains a release-host gate.

## Security and community settings

Before public visibility:

- enable private vulnerability reporting / Security Advisories so `SECURITY.md` has a real private channel;
- create a small starter set of issues from `docs/CONTRIBUTOR_BACKLOG.md`;
- use `good first issue` only for genuinely bounded tasks;
- configure branch protection / required CI where available;
- leave Discussions disabled until there is a real reason to use it rather than opening an empty community surface.

## External onboarding

While the repo is private, invite one external participant if practical and run `docs/EXTERNAL_ONBOARDING.md`. Their friction is evidence. Fix documentation/scripts before public promotion if they need private coaching to complete the expected path.

## Public switch

Only change visibility to public after the launch checklist is green through hosted CI and external onboarding. Immediately before the public tag, repeat the exact-name search, dependency/license audit, release verification, final artifact hash and demo inspection.
