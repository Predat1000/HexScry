import assert from "node:assert/strict";
import test from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inspectBinary, readBinaryWindowAtAddress } from "../src/index.js";

const testDir = dirname(fileURLToPath(import.meta.url));
const fixture = join(testDir, "..", "..", "..", "fixtures", "pe", "minimal-x64.exe");

test("parses the deterministic x64 PE corpus fixture", async () => {
  const report = await inspectBinary(fixture);
  assert.equal(report.format, "PE32+");
  assert.equal(report.architecture, "x86-64");
  assert.equal(report.imageBase, "0x140000000");
  assert.equal(report.entryPointRva, 0x1000);
  assert.equal(report.fileSize, 0x400);
  assert.equal(report.sha256, "134f2ecaa3e88b87d42e8ee146b9ad40ac0e985c576b028ceea2df7d5dbc139e");
  assert.deepEqual(report.sections.map((section) => section.name), [".text"]);
  assert.ok(report.strings.some((entry) => entry.value === "HexScry deterministic PE fixture"));

  const entry = await readBinaryWindowAtAddress(report, "0x140001000", 3);
  assert.equal(entry.fileOffset, 0x200);
  assert.deepEqual(entry.bytes, [0x31, 0xc0, 0xc3]);
});
