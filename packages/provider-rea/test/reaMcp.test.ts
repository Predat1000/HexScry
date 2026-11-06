import assert from "node:assert/strict";
import test from "node:test";
import { __mcpTest } from "../src/index.js";

test("normalizes list_procedures rows with classification", () => {
  const rows = __mcpTest.parseProcedures({
    normalized_result: [
      {
        address: "0x140001000",
        value: "entry",
        procedure: { external: false, thunk: false, thunk_target: null },
      },
      {
        address: "EXTERNAL:0x1",
        value: "KERNEL32.DLL::ReadFile",
        procedure: { external: true, thunk: false, thunk_target: null },
      },
    ],
  });

  assert.deepEqual(rows, [
    {
      address: "0x140001000",
      name: "entry",
      provider: "ghidra",
      external: false,
      thunk: false,
      thunkTarget: null,
    },
    {
      address: "EXTERNAL:0x1",
      name: "KERNEL32.DLL::ReadFile",
      provider: "ghidra",
      external: true,
      thunk: false,
      thunkTarget: null,
    },
  ]);
});

test("removes undefined values from MCP subprocess environment", () => {
  assert.deepEqual(__mcpTest.cleanEnvironment({ A: "1", B: undefined }), { A: "1" });
});

test("normalizes bounded provider byte reads", () => {
  assert.deepEqual(
    __mcpTest.parseMemoryByteWindow({
      normalized_result: {
        address: "0x140001010",
        requested_bytes: 4,
        returned_bytes: 4,
        bytes_hex: "4883ec28",
        complete: true,
      },
    }),
    {
      address: "0x140001010",
      requestedBytes: 4,
      returnedBytes: 4,
      bytes: [0x48, 0x83, 0xec, 0x28],
      complete: true,
    },
  );
});

test("rejects inconsistent provider byte coverage", () => {
  assert.throws(() =>
    __mcpTest.parseMemoryByteWindow({
      normalized_result: {
        address: "0x140001010",
        requested_bytes: 4,
        returned_bytes: 3,
        bytes_hex: "4883ec28",
        complete: false,
      },
    }),
  );
});

test("normalizes containing-procedure resolution", () => {
  const procedure = {
    address: "0x140001010",
    name: "FUN_140001010",
    classification: { external: false, thunk: false, thunk_target: null },
    body: { available: true },
  };
  assert.deepEqual(
    __mcpTest.parseProcedureResolution({
      normalized_result: { query_address: "0x140001018", found: true, procedure },
    }),
    {
      queryAddress: "0x140001018",
      procedure: {
        address: "0x140001010",
        name: "FUN_140001010",
        provider: "ghidra",
        external: false,
        thunk: false,
        thunkTarget: null,
      },
      reason: null,
    },
  );
});

test("preserves negative containing-procedure reason", () => {
  assert.deepEqual(
    __mcpTest.parseProcedureResolution({
      normalized_result: {
        query_address: "0x1",
        found: false,
        procedure: null,
        reason: "outside_segments",
      },
    }),
    { queryAddress: "0x1", procedure: null, reason: "outside_segments" },
  );
});

test("normalizes exact native-instruction evidence", () => {
  assert.deepEqual(
    __mcpTest.parseInstructionInspection({
      normalized_result: {
        address: "0x140001000",
        status: "decoded",
        procedure: "0x140001000",
        architecture: "x86_64",
        mode: "default",
        bytes: "31c0",
        length: 2,
        mnemonic: "XOR",
        raw_disassembly: "XOR EAX,EAX",
        operands: [
          { index: 0, raw: "EAX", provider_type: 1, components: [], memory_addressing: "unavailable" },
          { index: 1, raw: "EAX", provider_type: 1, components: [], memory_addressing: "unavailable" },
        ],
        flow: {
          kind: "fallthrough",
          conditional: false,
          computed: false,
          direct_destinations: ["0x140001002"],
        },
        references: [
          {
            target_address: "0x140001002",
            type: "FALL_THROUGH",
            call: false,
            jump: false,
            indirect: false,
            computed: false,
            operand_index: -1,
          },
        ],
        incoming_references: [],
        limitations: ["Static provider observation only."],
      },
    }),
    {
      address: "0x140001000",
      status: "decoded",
      procedure: "0x140001000",
      architecture: "x86_64",
      mode: "default",
      bytesHex: "31c0",
      length: 2,
      mnemonic: "XOR",
      rawDisassembly: "XOR EAX,EAX",
      operands: ["EAX", "EAX"],
      flow: {
        kind: "fallthrough",
        conditional: false,
        computed: false,
        directDestinations: ["0x140001002"],
      },
      outgoingReferences: [
        {
          sourceAddress: null,
          targetAddress: "0x140001002",
          type: "FALL_THROUGH",
          operandIndex: -1,
          tags: [],
        },
      ],
      incomingReferences: [],
      limitations: ["Static provider observation only."],
    },
  );
});

test("preserves non-decoded native-instruction status", () => {
  const result = __mcpTest.parseInstructionInspection({
    normalized_result: {
      address: "0x140001001",
      status: "not-instruction-boundary",
      procedure: "0x140001000",
      architecture: "x86_64",
      mode: "default",
      bytes: null,
      length: null,
      mnemonic: null,
      raw_disassembly: null,
      operands: [],
      flow: { kind: "unavailable", conditional: false, computed: false, direct_destinations: [] },
      references: [],
      incoming_references: null,
      limitations: ["Address is inside an instruction rather than at its boundary."],
    },
  });
  assert.equal(result.status, "not-instruction-boundary");
  assert.equal(result.rawDisassembly, null);
  assert.equal(result.incomingReferences, null);
});

test("preserves provider error detail and adds a Ghidra setup hint only when supported by evidence", () => {
  const error = __mcpTest.providerFailure(
    "open_binary",
    { content: [{ type: "text", text: "GHIDRA_INSTALL_DIR is missing" }] },
    "sample.exe",
  );
  assert.match(error.message, /GHIDRA_INSTALL_DIR is missing/);
  assert.match(error.message, /Verify Ghidra is installed/);
  assert.match(error.message, /sample\.exe/);
});

test("uses structured provider detail without inventing a setup diagnosis", () => {
  const error = __mcpTest.providerFailure(
    "analyze_function",
    { structuredContent: { message: "Unsupported target language" } },
    "0x401000",
  );
  assert.match(error.message, /Unsupported target language/);
  assert.doesNotMatch(error.message, /Verify Ghidra|Verify a compatible JDK/);
});

test("summarizes a timed-out Java probe for the requested provider", () => {
  const report = { error: { message: "Provider unavailable", details: {
    requested_provider_id: "ghidra", rejections: [
      { provider_id: "other", reason: "Other launcher missing" },
      { provider_id: "ghidra", reason: "Update JAVA_HOME", diagnostics: {
        java_probe_failure: { process_error_code: "ETIMEDOUT", output: "private system settings" },
      } },
    ],
  } } };
  for (const reply of [{ structuredContent: report }, { content: [{ text: JSON.stringify(report) }] }]) {
    const error = __mcpTest.providerFailure("open_binary", reply);
    assert.match(error.message, /Java runtime check timed out/);
    assert.doesNotMatch(error.message, /private system settings|JAVA_HOME|Other launcher|Verify Ghidra/);
  }
});