import assert from "node:assert/strict";
import test from "node:test";
import type { BinaryReport } from "../src/index.js";
import { addressToFileOffset } from "../src/index.js";

const report: BinaryReport = {
  path: "fixture.exe",
  fileName: "fixture.exe",
  fileSize: 0x1000,
  sha256: "a".repeat(64),
  format: "PE32+",
  architecture: "x86-64",
  machine: 0x8664,
  entryPointRva: 0x1010,
  imageBase: "0x140000000",
  timestamp: 0,
  sections: [
    {
      name: ".text",
      virtualAddress: 0x1000,
      virtualSize: 0x300,
      rawOffset: 0x200,
      rawSize: 0x200,
      characteristics: 0x60000020,
    },
  ],
  imports: [],
  exports: [],
  strings: [],
  limitations: [],
};

test("maps a virtual address into file-backed section bytes", () => {
  assert.equal(addressToFileOffset(report, "0x140001010"), 0x210);
});

test("does not pretend zero-filled virtual tail has file bytes", () => {
  assert.equal(addressToFileOffset(report, "0x140001250"), null);
});

test("rejects malformed or pre-image-base addresses", () => {
  assert.equal(addressToFileOffset(report, "not-an-address"), null);
  assert.equal(addressToFileOffset(report, "0x13fffffff"), null);
});
