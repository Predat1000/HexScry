# Branding review

`AxiomRE` was the original internal working name. Before public launch, the project was renamed to **HexScry** to reduce known naming/collision risk while the change was still cheap.

## Review performed — 2026-10-23

### Why AxiomRE was retired

- GitHub and npm did not show an exact reverse-engineering/software collision for `AxiomRE` at the time of review.
- General web search did surface an existing/recent insurance/reinsurance identity using `AxiomRe` / `AxiomRe, Inc.`. It is a different industry, but retaining a known external identity immediately before public launch offered no meaningful benefit.
- Earlier alternatives were rejected when they merely exchanged one collision for another: `Fathom Re` is used by an existing business and `HexLoom` is already used by a hex/reverse-engineering tool.

### HexScry checks

- GitHub repository search for exact `HexScry` / `HexScry in:name` returned no exact repository in the reviewed results.
- The npm registry had no published exact unscoped `hexscry` package in the review.
- Exact/general web searches did not surface a known reverse-engineering, security or software product named `HexScry`.
- Search-engine checks scoped toward major trademark registries did not surface an obvious `HexScry` result. This is **not** a substitute for formal trademark clearance.
- `hexscry.com` resolves in DNS and appears registered/parked or otherwise unavailable; it did not present useful public content during the check.
- `hexscry.dev`, `hexscry.org`, `hexscry.io` and `hexscry.net` did not resolve during the check.

## Decision

**Adopt `HexScry` as the public project/product name before the repository is published.**

The improvement is clear enough to justify the one-time rename now: it removes a known AxiomRe identity conflict, has no obvious software-community collision, fits the reverse-engineering purpose, and avoids carrying a provisional brand into public packages and project formats.

Before the first public tag, repeat name/package/repository checks and perform whatever formal trademark review is appropriate for the intended distribution markets. A later rename should require a concrete legal or confusion risk; branding churn by itself is not a product improvement.