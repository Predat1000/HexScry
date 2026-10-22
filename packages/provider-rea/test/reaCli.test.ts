import assert from "node:assert/strict";
import test from "node:test";
import { __test } from "../src/index.js";

test("normalizes REA procedure search rows", () => {
  const rows = __test.parseSearchProcedures(JSON.stringify({
    normalized_result: [
      { address: "0x140001000", value: "entry" },
      { address: "0x140002000", value: "FUN_140002000" },
    ],
  }));

  assert.deepEqual(rows, [
    { address: "0x140001000", name: "entry", provider: "ghidra" },
    { address: "0x140002000", name: "FUN_140002000", provider: "ghidra" },
  ]);
});

test("rejects malformed REA procedure rows", () => {
  assert.throws(
    () => __test.parseSearchProcedures(JSON.stringify({ normalized_result: [{ address: 12 }] })),
    /invalid address or name/,
  );
});

test("rejects responses without normalized_result", () => {
  assert.throws(
    () => __test.parseSearchProcedures(JSON.stringify({ ok: false })),
    /omitted normalized_result/,
  );
});
