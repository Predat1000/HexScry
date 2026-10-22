# Provisional branding review

`AxiomRE` remains a working codename. It is not yet approved as the final public product name.

## Checks performed — 2026-10-23

- GitHub repository search for `AxiomRE` / `AxiomRE in:name` did not surface an exact reverse-engineering project using that repository name in the reviewed results. Similar names such as AxiomRelay, AxiomRed and AxiomResearch exist.
- The npm registry returned 404 for the exact unscoped package name `axiomre` at the time of review.
- General web search surfaced an existing/recently indexed insurance/reinsurance business identity using `AxiomRe` / `AxiomRe, Inc.`. This is a different industry, but it is enough that we should not treat the name as legally cleared merely because developer registries are free.

## Decision

Keep `AxiomRE` internally because renaming now would create churn without solving a demonstrated software-community collision. Before public branding or release:

1. repeat GitHub/package/major search-engine checks close to launch;
2. perform an appropriate trademark/name review in the intended distribution markets;
3. change the name before public launch if that review shows meaningful confusion or legal risk.

The codebase must therefore avoid assumptions that the final product/repository/package will permanently be called `AxiomRE`.
