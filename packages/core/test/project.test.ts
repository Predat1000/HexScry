import assert from "node:assert/strict";
import test from "node:test";
import type { BinaryReport } from "../src/index.js";
import { createProject, parseProject, verifyProjectTarget } from "../src/index.js";

const report: BinaryReport = {
  path: "C:\\fixtures\\sample.exe",
  fileName: "sample.exe",
  fileSize: 4096,
  sha256: "a".repeat(64),
  format: "PE32+",
  architecture: "x86-64",
  machine: 0x8664,
  entryPointRva: 0x1000,
  imageBase: "0x140000000",
  timestamp: 0,
  sections: [],
  imports: [],
  exports: [],
  strings: [],
  limitations: [],
};

test("round-trips the minimal project document", () => {
  const project = createProject(report, "0x140001000");
  assert.deepEqual(parseProject(JSON.stringify(project)), project);
});

test("rejects unsupported project versions", () => {
  const project = createProject(report);
  assert.throws(() => parseProject(JSON.stringify({ ...project, version: 2 })), /Unsupported/);
});

test("detects when a project points at different target bytes", () => {
  const project = createProject(report);
  assert.throws(
    () => verifyProjectTarget(project, { ...report, sha256: "b".repeat(64) }),
    /hash mismatch/,
  );
});

test("round-trips analyst aliases and comments", () => {
  const project = createProject(report, "0x140001000", {
    aliases: { "0x140001000": "parse_header" },
    comments: { "0x140001000": "Likely validates the PE header before dispatch." },
  });
  assert.deepEqual(parseProject(JSON.stringify(project)), project);
});

test("loads legacy v1 projects without annotations", () => {
  const project = createProject(report, "0x140001000");
  const { annotations: _annotations, ...legacy } = project;
  assert.deepEqual(parseProject(JSON.stringify(legacy)).annotations, { aliases: {}, comments: {} });
});

test("rejects oversized analyst annotations", () => {
  const project = createProject(report);
  assert.throws(
    () => parseProject(JSON.stringify({
      ...project,
      annotations: { aliases: { "0x140001000": "x".repeat(129) }, comments: {} },
    })),
    /alias annotation is invalid/,
  );
});


test("writer rejects annotations that the project reader would reject", () => {
  assert.throws(
    () => createProject(report, null, { aliases: {}, comments: { "0x140001000": "x".repeat(4001) } }),
    /comment annotation is invalid/,
  );
});

test("writer rejects an invalid selected procedure instead of creating an unreadable project", () => {
  assert.throws(
    () => createProject(report, ""),
    /selected procedure is invalid/,
  );
});
