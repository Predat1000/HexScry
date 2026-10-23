# PE fixture corpus

`minimal-x64.exe` is generated entirely by `scripts/generate-fixtures.mjs` from project-owned code. It contains no third-party executable bytes.

Properties:

- PE32+ / AMD64;
- image base `0x140000000`;
- entry RVA `0x1000`;
- one executable/readable `.text` section;
- entry machine code: `xor eax, eax; ret`;
- deterministic timestamp and padding;
- embedded marker string: `HexScry deterministic PE fixture`.

Regenerate with:

```text
node scripts/generate-fixtures.mjs
```

The generated fixture is covered by the repository license and exists only for parser/provider regression tests.
