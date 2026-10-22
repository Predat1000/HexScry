import assert from "node:assert/strict";
import test from "node:test";
import { __mcpTest } from "../src/index.js";

const capturedShape = {
  normalized_result: {
    procedure: {
      address: "0x140001010",
      name: "FUN_140001010",
      signature: "int FUN_140001010(void)",
      locals: [],
      classification: {
        external: false,
        thunk: false,
        thunk_target: null,
        provenance: "ghidra-function-manager",
      },
      body: {
        available: true,
        provenance: "ghidra-function-body-address-set",
        ranges: [{ start: "0x140001010", end: "0x14000102f" }],
        total_bytes: 32,
        span_bytes: 32,
        non_contiguous: false,
        contains_entry: true,
      },
    },
    pseudocode: "int FUN_140001010(void) {\n  return 0;\n}",
    assembly: ["PUSH RBP", "MOV RBP,RSP", "RET"],
    comments: [],
    callers: [],
    callees: [],
    incoming_references: [
      {
        source_address: "0x140002000",
        target_address: "0x140001010",
        source_procedure: null,
        target_procedure: null,
        kind: { available: true, type: "DATA", data: true, read: true },
      },
    ],
    outgoing_references: [
      {
        source_address: "0x140001018",
        target_address: "0x140003000",
        source_procedure: null,
        target_procedure: null,
        kind: { available: false, reason: "provider classification unavailable" },
      },
    ],
    referenced_strings: [],
    referenced_names: [],
    basic_blocks: [],
    native_api: null,
    native_value_flow: null,
    facet_availability: {
      pseudocode: { available: true },
      assembly: { available: true },
    },
    limitations: ["Synthetic fixture derived from the observed REA dossier shape."],
  },
};

test("normalizes the function dossier fields AxiomRE currently consumes", () => {
  assert.deepEqual(__mcpTest.parseFunctionDossier(capturedShape), {
    procedure: {
      address: "0x140001010",
      name: "FUN_140001010",
      provider: "ghidra",
      external: false,
      thunk: false,
      thunkTarget: null,
    },
    signature: "int FUN_140001010(void)",
    pseudocode: "int FUN_140001010(void) {\n  return 0;\n}",
    assembly: ["PUSH RBP", "MOV RBP,RSP", "RET"],
    callers: [],
    callees: [],
    incomingReferences: [
      {
        sourceAddress: "0x140002000",
        targetAddress: "0x140001010",
        sourceProcedure: null,
        targetProcedure: null,
        type: "DATA",
        tags: ["data", "read"],
        limitation: null,
      },
    ],
    outgoingReferences: [
      {
        sourceAddress: "0x140001018",
        targetAddress: "0x140003000",
        sourceProcedure: null,
        targetProcedure: null,
        type: null,
        tags: [],
        limitation: "provider classification unavailable",
      },
    ],
    limitations: ["Synthetic fixture derived from the observed REA dossier shape."],
  });
});

test("rejects a dossier without executable code facets", () => {
  assert.throws(
    () => __mcpTest.parseFunctionDossier({
      normalized_result: {
        ...capturedShape.normalized_result,
        assembly: "not-an-array",
      },
    }),
    /code facets are invalid/,
  );
});
