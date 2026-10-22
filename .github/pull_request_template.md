## What changed?

<!-- Describe the user-visible or engineering change. -->

## Why this approach?

<!-- Note important tradeoffs, rejected alternatives or architectural implications. -->

## Verification

- [ ] `npm run check`
- [ ] `npm run smoke:rea` when the REA/Ghidra adapter is affected and the external toolchain is available
- [ ] New or changed behavior has regression coverage where practical

## Safety / provenance

- [ ] No proprietary source code, private data, credentials or unlicensed binary fixtures are included
- [ ] Provider-specific structures remain behind adapters rather than leaking into React/core contracts
- [ ] Any new limitation or uncertainty is represented explicitly rather than inferred away

## Follow-up

<!-- Optional: list known limitations or intentionally deferred work. -->
